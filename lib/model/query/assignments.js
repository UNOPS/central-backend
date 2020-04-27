// Copyright 2019 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const { map } = require('ramda');
const { withJoin, QueryOptions } = require('../../util/db');

module.exports = {
  // we have to be specific about assignments.acteeId, since the extended version
  // of the request also pulls an actee column from actors.
  // TODO: it does seem ugly though
  getByActeeId: (acteeId, options) => ({ assignments }) =>
    assignments._get(options.withCondition({ 'assignments.acteeId': acteeId })),

  getByActeeAndRoleId: (acteeId, roleId, options) => ({ assignments }) =>
    assignments._get(options.withCondition({ 'assignments.acteeId': acteeId, roleId })),

  _get: (options) => ({ db, simply, Assignment, Actor }) => ((options.extended !== true)
    ? simply.getWhere('assignments', options.condition, Assignment)
    : withJoin('assignment', { assignment: Assignment.Extended, actor: Actor }, (fields, unjoin) =>
      db.select(fields)
        .from('assignments')
        .where(options.condition)
        .innerJoin('actors', 'actors.id', 'assignments.actorId')
        .then(map(unjoin)))),

  getForFormsByProjectId: (projectId, options = QueryOptions.none) => ({ assignments }) =>
    assignments._getForForms(options.withCondition({ projectId })),

  getForFormsByProjectAndRoleId: (projectId, roleId, options = QueryOptions.none) => ({ assignments }) =>
    assignments._getForForms(options.withCondition({ projectId, roleId })),

  _getForForms: (options) => ({ db, Actor, Assignment, Form }) => ((options.extended !== true)
    // TODO: in this case, note that we don't return any particular Instance;
    // rather, we just return data objects that are returned directly over the
    // api. for now this will do but eventually it would be good to be consistent.
    ? db.select({ xmlFormId: 'forms.xmlFormId', roleId: 'assignments.roleId', actorId: 'assignments.actorId' })
      .from('assignments')
      .innerJoin('forms', 'forms.acteeId', 'assignments.acteeId')
      .where(options.condition)
    : withJoin('assignment', { assignment: Assignment.FormSummary, actor: Actor, form: Form }, (fields, unjoin) =>
      db.select(fields)
        .from('assignments')
        .innerJoin('forms', 'forms.acteeId', 'assignments.acteeId')
        .innerJoin('actors', 'actors.id', 'assignments.actorId')
        .where(options.condition)
        .then(map(unjoin)))),

  deleteByActorId: (actorId) => ({ db }) => db.delete().from('assignments').where({ actorId }),
  deleteByActeeId: (acteeId) => ({ db }) => db.delete().from('assignments').where({ acteeId })
};

