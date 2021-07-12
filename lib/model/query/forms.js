// Copyright 2017 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const { sql } = require('slonik');
const { map, compose, always } = require('ramda');
const { Frame, into } = require('../frame');
const { Actor, Blob, Form } = require('../frames');
const { getFormFields } = require('../../data/schema');
const { generateToken } = require('../../util/crypto');
const { unjoiner, extender, updater, equals, insert, insertMany, markDeleted, QueryOptions } = require('../../util/db');
const { resolve, reject, ignoringResult } = require('../../util/promise');
const { splitStream } = require('../../util/stream');
const { construct } = require('../../util/util');
const Option = require('../../util/option');
const Problem = require('../../util/problem');


////////////////////////////////////////////////////////////////////////////////
// IMPORT

// given binary stream, sends that stream to the configured xlsform transformation
// service and if successful returns the same result fromXml would, but with an
// additional xlsBlobId column pointing at the xls file blob id.
const fromXls = (stream, contentType, formIdFallback, ignoreWarnings) => ({ Blobs, xlsform }) =>
  splitStream(stream,
    ((s) => xlsform(s, formIdFallback)),
    ((s) => Blob.fromStream(s, contentType)))
    .then(([ { xml, itemsets, warnings }, blob ]) =>
      (((warnings.length > 0) && !ignoreWarnings)
        ? reject(Problem.user.xlsformWarnings({ warnings }))
        : Promise.all([ Form.fromXml(xml), Blobs.ensure(blob) ])
          .then(([ partial, xlsBlobId ]) => partial.withAux('xls', { xlsBlobId, itemsets }))));


////////////////////////////////////////////////////////////////////////////////
// CREATING NEW FORMS+VERSIONS

const _createNew = (form, def, project, publish) => ({ oneFirst, Actees, Forms }) =>
  Actees.provision('form', project)
    .then((actee) => oneFirst(sql`
with def as
  (insert into form_defs ("formId", xml, name, hash, sha, sha256, version, "keyId", "xlsBlobId", "draftToken", "createdAt", "publishedAt")
  values (nextval(pg_get_serial_sequence('forms', 'id')), ${form.xml}, ${def.name}, ${def.hash}, ${def.sha}, ${def.sha256}, ${def.version}, ${def.keyId}, ${form.xls.xlsBlobId || null}, ${(publish !== true) ? generateToken() : null}, clock_timestamp(), ${(publish === true) ? sql`clock_timestamp()` : null})
  returning *),
form as
  (insert into forms (id, "xmlFormId", state, "projectId", ${sql.identifier([ (publish === true) ? 'currentDefId' : 'draftDefId' ])}, "acteeId", "createdAt")
  select def."formId", ${form.xmlFormId}, ${form.state || 'open'}, ${project.id}, def.id, ${actee.id}, def."createdAt" from def
  returning forms.*)
select id from form`))
    .then(() => Forms.getByProjectAndXmlFormId(project.id, form.xmlFormId, false,
      (publish === true) ? undefined : Form.DraftVersion))
    .then((option) => option.get());

const createNew = (partial, project, publish = false) => ({ run, FormAttachments, Forms, Keys }) =>
  Promise.all([
    partial.aux.key.map(Keys.ensure).orElse(resolve(null)),
    getFormFields(partial.xml)
  ])
    .then(([ keyId, fields ]) => Forms._createNew(partial, partial.def.with({ keyId }), project, publish)
      .then((savedForm) => {
        const ids = { formId: savedForm.id, formDefId: savedForm.def.id };
        return Promise.all([
          FormAttachments.createNew(partial.xml, savedForm, partial.xls.itemsets),
          run(insertMany(fields.map((field) => new Form.Field(Object.assign(field, ids)))))
        ])
          .then(always(savedForm));
      }));

// (if we are asked to publish right away, log that too:)
createNew.audit = (form, partial, _, publish) => (log) =>
  log('form.create', form).then(() => ((publish === true)
    ? log('form.update.publish', form, { newDefId: form.currentDefId })
    : null));
createNew.audit.withResult = true;

// creates a new version (formDef) of an existing form.
//
// if publish is true, the new version supplants the published (currentDefId)
// version. if publish is false, it will supplant the draft (draftDefId) version.
// in actual practice, we only pass publish=true when enabling managed encryption,
// and we do not allow a draft version (in API logic) to be created if one already
// exists.
//
// if field paths/types collide, the database will complain.

const _getDraftToken = (form) => {
  if ((form.def.id != null) && (form.draftDefId === form.def.id)) return form.def.draftToken;
  return generateToken();
};
const createVersion = (partial, form, publish = false) => ({ run, one, FormAttachments, Forms, Keys }) => {
  if (form.xmlFormId !== partial.xmlFormId)
    return reject(Problem.user.unexpectedValue({ field: 'xmlFormId', value: partial.xmlFormId, reason: 'does not match the form you are updating' }));

  return Promise.all([
    // ensure the encryption key exists, then make sure our new def is in the
    // database, and mark it as either draft or current.
    partial.aux.key.map(Keys.ensure).orElse(resolve(null))
      .then((keyId) => partial.def.with({ formId: form.id, keyId, xlsBlobId: partial.xls.xlsBlobId }))
      .then((def) => ((publish === true)
        ? def.with({ publishedAt: new Date(), xml: partial.xml })
        : def.with({ draftToken: _getDraftToken(form), xml: partial.xml })))
      .then(compose(one, insert))
      .then(ignoringResult((savedDef) => ((publish === true)
        ? Forms._update(form, { currentDefId: savedDef.id })
        : Forms._update(form, { draftDefId: savedDef.id })))),
    // process the form schema locally while everything happens
    getFormFields(partial.xml)
  ])
    .then(([ savedDef, fields ]) => {
      // deal with fields for a moment; we just need to attach a bunch of ids
      // to them for storage.
      const ids = { formId: form.id, formDefId: savedDef.id };
      const fieldsForInsert = new Array(fields.length);
      for (let i = 0; i < fields.length; i += 1)
        fieldsForInsert[i] = new Form.Field(Object.assign({}, fields[i], ids));

      return Promise.all([
        run(insertMany(fieldsForInsert)),
        FormAttachments.createVersion(partial.xml, form, savedDef, partial.xls.itemsets, publish)
      ])
        .then(always(savedDef));
    });
};
createVersion.audit = (newDef, partial, form, _, publish) => (log) => ((publish === true)
  ? log('form.update.publish', form, { oldDefId: form.currentDefId, newDefId: newDef.id })
  : log('form.update.draft.set', form, { oldDraftDefId: form.draftDefId, newDraftDefId: newDef.id }));
createVersion.audit.withResult = true;


////////////////////////////////////////////////////////////////////////////////
// PUBLISHING MANAGEMENT

// TODO: we need to make more explicit what .def actually represents throughout.
// for now, enforce an extra check here just in case.
const publish = (form) => ({ Forms }) => {
  if (form.draftDefId !== form.def.id) throw Problem.internal.unknown();

  return Promise.all([
    Forms._update(form, { currentDefId: form.draftDefId, draftDefId: null }),
    Forms._updateDef(form, { draftToken: null, enketoId: null, publishedAt: (new Date()).toISOString() })
  ])
    .catch(Problem.translate(
      Problem.user.uniquenessViolation,
      () => Problem.user.versionUniquenessViolation({ xmlFormId: form.xmlFormId, version: form.def.version })
    ));
};
publish.audit = (form) => (log) => log('form.update.publish', form,
  { oldDefId: form.currentDefId, newDefId: form.draftDefId });

const clearDraft = (form) => ({ Forms }) => Forms._update(form, { draftDefId: null });


////////////////////////////////////////////////////////////////////////////////
// BASIC CRUD

// only updates the form. rn everywhere we update the def we do it separately.
// also, we provide these _update(Def) internally which will not log for internal
// actions.
const _update = (form, data) => ({ one }) => one(updater(form, data));
const update = (form, data) => ({ Forms }) => Forms._update(form, data);
update.audit = (form, data) => (log) => log('form.update', form, { data });

const _updateDef = (form, data) => ({ one }) => one(updater(form.def, data));

const del = (form) => ({ run, Assignments }) =>
  Promise.all([ run(markDeleted(form)), Assignments.revokeByActeeId(form.acteeId) ]);
del.audit = (form) => (log) => log('form.delete', form);


////////////////////////////////////////////////////////////////////////////////
// ENCRYPTION

// takes a Key object and a suffix to add to the form version string.
// we are always given primary formdefs. we also, however, need to update drafts
// if we have them.
// we also must do the work sequentially, so the currentDefId/draftDefId are not
// mutually clobbered.
const setManagedKey = (form, key, suffix) => ({ Forms }) => {
  let work;

  if (form.currentDefId != null) {
    // paranoia:
    if (form.def.id !== form.currentDefId)
      throw new Error('setManagedKey must be called with the current published def!');

    work = form.withManagedKey(key, suffix)
      .then((partial) => ((partial === false) ? null : Forms.createVersion(partial, form, true)));
  } else {
    work = resolve();
  }

  if (form.draftDefId != null)
    work = work.then(() =>
      Forms.getByProjectAndXmlFormId(form.projectId, form.xmlFormId, true, Form.DraftVersion)
        .then((option) => option.get()) // in transaction; guaranteed
        .then((draftForm) => draftForm.withManagedKey(key, suffix))
        .then((partial) => ((partial === false) ? null : Forms.createVersion(partial, form, false))));

  return work;
};


////////////////////////////////////////////////////////////////////////////////
// OPENROSA FORMLIST

const _openRosaJoiner = unjoiner(Form, Form.Def, Frame.define(into('openRosa'), 'hasAttachments'));
const getByAuthForOpenRosa = (projectId, auth, options = QueryOptions.none) => ({ all }) => all(sql`
select ${_openRosaJoiner.fields} from forms
left outer join form_defs on form_defs.id=forms."currentDefId"
left outer join
  (select "formDefId", count("formDefId" > 0) as "hasAttachments" from form_attachments
    group by "formDefId") as fa
  on forms."currentDefId"=fa."formDefId"
inner join
  (select forms.id from forms
    inner join projects on projects.id=forms."projectId"
    inner join
      (select "acteeId" from assignments
        inner join (select id from roles where verbs ? 'form.read') as role
          on role.id=assignments."roleId"
        where "actorId"=${auth.actor.map((actor) => actor.id).orElse(-1)}) as assignment
      on assignment."acteeId" in ('*', 'form', projects."acteeId", forms."acteeId")
    group by forms.id) as filtered
  on filtered.id=forms.id
where "projectId"=${projectId} and state not in ('closing', 'closed') and "currentDefId" is not null
  ${options.ifArg('formID', (xmlFormId) => sql` and "xmlFormId"=${xmlFormId}`)} and "deletedAt" is null
order by coalesce(form_defs.name, forms."xmlFormId") asc`)
  .then(map(_openRosaJoiner));


////////////////////////////////////////////////////////////////////////////////
// GETS

// helper function to gate how form defs are joined to forms in _get
/* eslint-disable indent */
const versionJoinCondition = (version) => (
  (version === '___') ? versionJoinCondition('') :
  (version == null) ? sql`form_defs.id=coalesce(forms."currentDefId", forms."draftDefId")` :
  (version === Form.DraftVersion) ? sql`form_defs.id=forms."draftDefId"` :
  (version === Form.PublishedVersion) ? sql`form_defs.id=forms."currentDefId"` :
  (version === Form.AllVersions) ? sql`form_defs."formId"=forms.id and form_defs."publishedAt" is not null` :
  sql`form_defs."formId"=forms.id and form_defs.version=${version} and form_defs."publishedAt" is not null`
);
/* eslint-enable indent */


const _getVersions = extender(Form, Form.Def)(Form.ExtendedVersion, Option.of(Actor.into('publishedBy')))((fields, extend, options, formId) => sql`
select ${fields} from forms
join form_defs on ${versionJoinCondition(Form.AllVersions)}
${extend|| sql`
  left outer join (select * from audits where action='form.update.publish') as audits
    on forms."acteeId"=audits."acteeId" and audits.details->'newDefId'=to_jsonb(form_defs.id)
  left outer join actors on audits."actorId"=actors.id
  left outer join (select id, "contentType" as "excelContentType" from blobs) as xls
    on form_defs."xlsBlobId"=xls.id`}
where forms.id=${formId} and forms."deletedAt" is null
order by "publishedAt" desc`);
const getVersions = (formId, options = QueryOptions.none) => ({ all }) => _getVersions(all, options, formId);


const _updateUnjoiner = unjoiner(Form, Form.Def);
const getByActeeIdForUpdate = (acteeId, options, version) => ({ maybeOne }) => maybeOne(sql`
select ${_updateUnjoiner.fields} from forms
join form_defs on ${versionJoinCondition(version)}
where "acteeId"=${acteeId} and "deletedAt" is null
for update`)
  .then(map(_updateUnjoiner));


// there are many combinations of required fields here so we compose our own extender variant.
const _getSql = ((fields, extend, options, version) => sql`
select ${fields} from forms
left outer join form_defs on ${versionJoinCondition(version)}
${extend|| sql`
  left outer join
    (select "formId", count(id)::integer as "submissions", max("createdAt") as "lastSubmission" from submissions
      where draft=${version === Form.DraftVersion} and "deletedAt" is null
      group by "formId") as submission_stats
    on forms.id=submission_stats."formId"
  left outer join (select * from audits where action='form.create') as audits
    on forms."acteeId"=audits."acteeId"
  left outer join actors on audits."actorId"=actors.id
  left outer join (select id, "contentType" as "excelContentType" from blobs) as xls
    on form_defs."xlsBlobId"=xls.id`}
where ${equals(options.condition)} and forms."deletedAt" is null
order by coalesce(form_defs.name, "xmlFormId") asc`);

const _getWithoutXml = extender(Form, Form.Def)(Form.Extended, Actor.into('createdBy'))(_getSql);
const _getWithXml = extender(Form, Form.Def, Form.Xml)(Form.Extended, Actor.into('createdBy'))(_getSql);
const _get = (exec, options, xml, version) =>
  ((xml === true) ? _getWithXml : _getWithoutXml)(exec, options, version);

const getByProjectId = (projectId, xml, version, options = QueryOptions.none) => ({ all }) =>
  _get(all, options.withCondition({ projectId }), xml, version);
const getByProjectAndXmlFormId = (projectId, xmlFormId, xml, version, options = QueryOptions.none) => ({ maybeOne }) =>
  _get(maybeOne, options.withCondition({ projectId, xmlFormId }), xml, version);


////////////////////////////////////////////////////////////////////////////////
// SCHEMA

const getFields = (formDefId) => ({ all }) =>
  all(sql`select * from form_fields where "formDefId"=${formDefId} order by "order" asc`)
    .then(map(construct(Form.Field)));

const getBinaryFields = (formDefId) => ({ all }) =>
  all(sql`select * from form_fields where "formDefId"=${formDefId} and "binary"=true order by "order" asc`)
    .then(map(construct(Form.Field)));


////////////////////////////////////////////////////////////////////////////////
// MISC

const lockDefs = () => ({ run }) => run(sql`lock form_defs in share mode`);

const getAllSubmitters = (formId) => ({ all }) => all(sql`
select actors.* from actors
inner join
  (select "submitterId" from submissions
    where "deletedAt" is null and "formId"=${formId}
    group by "submitterId")
  as submitters on submitters."submitterId"=actors.id
order by actors."displayName" asc`)
  .then(map(construct(Actor)));


module.exports = {
  fromXls, _createNew, createNew, createVersion,
  publish, clearDraft,
  _update, update, _updateDef, del,
  setManagedKey,
  getByAuthForOpenRosa,
  getVersions, getByActeeIdForUpdate, getByProjectId, getByProjectAndXmlFormId,
  getFields, getBinaryFields,
  lockDefs, getAllSubmitters
};

