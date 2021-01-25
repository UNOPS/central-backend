// Copyright 2017 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const { resultCount, wasUpdateSuccessful } = require('../../util/db');
const { resolve } = require('../../util/promise');
const { flatten, uniq, map, compose } = require('ramda');

module.exports = {
  create: (actor) => ({ actees, simply }) =>
    actees.provision(actor.type)
      .then((actee) => simply.create('actors', actor.with({ acteeId: actee.id }))),

  // Probably poorly named; this has nothing to do with X-Extended-Metadata responses.
  // Instead, it is a helper that given any Instance that contains an actor: Actor
  // property will create bot the Actor as well as that Instance in a transaction.
  createExtended: (extended, extendedTable) => ({ actors, simply }) =>
    actors.create(extended.actor)
      .then((savedActor) => simply.create(extendedTable, extended.with({ actor: savedActor }))
        .then((savedExtended) => savedExtended.with({ actor: savedActor }))),

  getById: (id) => ({ simply, Actor }) =>
    simply.getOneWhere('actors', { id, deletedAt: null }, Actor),

  // permissions queries:
  assignRole: (actorId, roleId, acteeId) => ({ db }) =>
    db.insert({ actorId, roleId, acteeId }).into('assignments').then(() => true),

  unassignRole: (actorId, roleId, acteeId) => ({ db }) =>
    db.delete().from('assignments').where({ actorId, roleId, acteeId })
      .then(wasUpdateSuccessful),

  // TODO: project permissions cascading needs to be more straightforward than this.
  extraActeeIdsFor: (actor) => ({ db }) => {
    if (actor.type === 'field_key')
      return db.select('projects.acteeId')
        .from('projects')
        .innerJoin('field_keys', { actorId: actor.id, 'field_keys.projectId': 'projects.id' })
        .then(([{ acteeId }]) => [ acteeId ]);

    if (actor.type === 'public_link')
      return db.select({ projectActeeId: 'projects.acteeId', formActeeId: 'forms.acteeId' })
        .from('forms')
        .innerJoin('public_links', { actorId: actor.id, 'public_links.formId': 'forms.id' })
        .innerJoin('projects', 'projects.id', 'forms.projectId')
        .then(([{ projectActeeId, formActeeId }]) => [ projectActeeId, formActeeId ]);

    return resolve([]);
  },

  can: (actor, verb, actee) => ({ db }) =>
    resolve(actee.acteeIds()).then((acteeIds) =>
      db.count('*')
        .from('assignments')
        .where({ actorId: actor.id })
        .whereIn('acteeId', acteeIds)
        .innerJoin(
          db.select('id').from('roles').whereRaw('verbs \\? ?', verb).as('role'),
          'role.id', 'assignments.roleId'
        )
        .limit(1)
        .then(resultCount)
        .then((count) => count > 0)),

  verbsOn: (actorId, actee) => ({ db }) =>
    resolve(actee.acteeIds()).then((acteeIds) =>
      db.select('verbs')
        .from('roles')
        .innerJoin(
          db.select('roleId').from('assignments')
            .where({ actorId })
            .whereIn('acteeId', acteeIds)
            .as('assignments'),
          'assignments.roleId', 'roles.id'
        )
        // TODO: it miiiiight be possible to make postgres do this work?
        .then(compose(uniq, flatten, map((r) => r.verbs))))
};

