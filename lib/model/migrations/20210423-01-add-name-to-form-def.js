// Copyright 2021 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const { Form } = require('../frames');

const up = async (db) => {
  // All column "name" to form_defs to store the title of a form
  // Most places in central, the name of a form is called the "name"
  // and only in the XForm/XLSForm is it called "title", so we are going
  // with calling it "name" everywhere in the code, even in the database.
  await db.schema.table('form_defs', (fd) => {
    fd.text('name');
  });

  await db.raw('ALTER TABLE form_defs DISABLE TRIGGER check_managed_key');

  const work = [];
  for await (const def of db.select('*').from('form_defs').stream()) {
    const partial = await Form.fromXml(def.xml);
    if (partial.def.name == null) continue;

    const data = { name: partial.def.name };
    work.push(db.update(data).into('form_defs').where({ id: def.id }));
  }
  await Promise.all(work);

  await db.raw('ALTER TABLE form_defs ENABLE TRIGGER check_managed_key');
};

const down = (db) => db.schema.table('form_defs', (fd) => {
  fd.dropColumn('name');
});

module.exports = { up, down };

