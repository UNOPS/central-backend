const appRoot = require('app-root-path');
const should = require('should');
const uuid = require('uuid/v4');
const { createReadStream, readFileSync } = require('fs');
const { testService } = require('../setup');
const testData = require('../../data/xml');
const { zipStreamToFiles } = require('../../util/zip');
const { exhaust } = require(appRoot + '/lib/worker/worker');

describe('api: /submission', () => {
  describe('HEAD', () => {
    it('should return a 204 with no content', testService((service) =>
      service.head('/v1/projects/1/submission')
        .set('X-OpenRosa-Version', '1.0')
        .expect(204)));

    it('should fail if not given X-OpenRosa-Version header', testService((service) =>
      service.head('/v1/projects/1/submission')
        .expect(400)));

    it('should fail on authentication given broken credentials', testService((service) =>
      service.head('/v1/key/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/projects/1/submission')
        .set('X-OpenRosa-Version', '1.0')
        .expect(403)));
  });

  describe('POST', () => {
    it('should reject if no xml file is given', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .set('Content-Type', 'text/xml')
          .send(testData.instances.simple2.one)
          .expect(400)
          .then(({ text }) => {
            text.should.match(/Required multipart POST field xml_submission_file missing./);
          }))));

    it('should reject if the xml is not valid', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from('<test'), { filename: 'data.xml' })
          .expect(400)
          .then(({ text }) => { text.should.match(/form ID xml attribute/i); }))));

    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from('<data id="nonexistent"><field/></data>'), { filename: 'data.xml' })
          .expect(404))));

    it('should reject if the user cannot submit', testService((service) =>
      service.post('/v1/projects/1/submission')
        .set('X-OpenRosa-Version', '1.0')
        .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
        .expect(401)));

    it('should reject if the form is not taking submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.patch('/v1/projects/1/forms/simple')
          .send({ state: 'closed' })
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
            .expect(409)))));

    it('should reject if the submission version does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from('<data id="simple" version="-1"><orx:meta><orx:instanceID>one</orx:instanceID></orx:meta></data>'), { filename: 'data.xml' })
          .expect(404))));

    it('should save the submission to the appropriate form without device id', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(201)
          .then(({ text }) => {
            text.should.match(/upload was successful/);
          })
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/simple/submissions/one')
              .expect(200)
              .then(({ body }) => {
                body.createdAt.should.be.a.recentIsoDate();
                should.not.exist(body.deviceId);
              }),
            asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
              .expect(200)
              .then(({ text }) => { text.should.equal(testData.instances.simple.one); })
          ])))));

    it('should save the submission to the appropriate form with device id as null when query string is empty', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission?deviceID=')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(201)
          .then(({ text }) => {
            text.should.match(/upload was successful/);
          })
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/simple/submissions/one')
              .expect(200)
              .then(({ body }) => {
                body.createdAt.should.be.a.recentIsoDate();
                should.not.exist(body.deviceId);
              }),
            asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
              .expect(200)
              .then(({ text }) => { text.should.equal(testData.instances.simple.one); })
          ])))));

    it('should save the submission to the appropriate form with device id', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission?deviceID=imei%3A358240051111110')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(201)
          .then(({ text }) => {
            text.should.match(/upload was successful/);
          })
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/simple/submissions/one')
              .expect(200)
              .then(({ body }) => {
                body.createdAt.should.be.a.recentIsoDate();
              body.deviceId.should.equal('imei:358240051111110');
              }),
            asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
              .expect(200)
              .then(({ text }) => { text.should.equal(testData.instances.simple.one); })
          ])))));

    it('should accept a submission for an old form version', testService((service, { simply, SubmissionDef, FormDef }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=three')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from('<data id="simple" version="two"><orx:meta><orx:instanceID>one</orx:instanceID></orx:meta></data>'), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
            .expect(200))
          // the submission worked, that's good. the rest of this checks that it went
          // to the correct place.
          .then(() => SubmissionDef.getCurrentByIds(1, 'simple', 'one', false))
          .then((o) => o.get())
          .then(({ formDefId }) => simply.getOneWhere('form_defs', { id: formDefId }, FormDef))
          .then((o) => o.get())
          .then((formDef) => {
            formDef.version.should.equal('two');
          }))));

    it('should store the correct formdef and actor ids', testService((service, { db }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(201)
          .then(() => Promise.all([
            asAlice.get('/v1/users/current').then(({ body }) => body.id),
            db.select('formDefId', 'submitterId').from('submission_defs')
          ]))
          .then(([ aliceId, submissions ]) => {
            submissions.length.should.equal(1);
            submissions[0].submitterId.should.equal(aliceId);
            return db.select('xml').from('form_defs').where({ id: submissions[0].formDefId })
              .then(([ def ]) => {
                def.xml.should.equal(testData.forms.simple);
              });
          }))));

    // also tests /forms/_/submissions/_/attachments return content. (mark1)
    // no point in replicating it.
    it('should save given attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { name: 'here_is_file2.jpg', exists: true },
                  { name: 'my_file1.mp4', exists: true }
                ]);
              }))))));

    it('should return an appropriate error given conflicting attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('file1', Buffer.from('this is test file three'), { filename: 'file1' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.conflict), { filename: 'data.xml' })
            .attach('file1', Buffer.from('this is test file four'), { filename: 'file1' })
            .expect(409)))));

    it('should not fail given identical attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('my_file1.mp4', Buffer.from('this is a test file'), { filename: 'my_file1.mp4' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('here_is_file2.jpg', Buffer.from('this is a test file'), { filename: 'here_is_file2.jpg' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { name: 'here_is_file2.jpg', exists: true },
                  { name: 'my_file1.mp4', exists: true }
                ]);
              }))))));

    it('should create audit log entries for saved attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .expect(201)
            .then(() => Promise.all([
              asAlice.get('/v1/audits?action=submission.attachment.update').then(({ body }) => body),
              asAlice.get('/v1/users/current').then(({ body }) => body)
            ]))
            .then(([ audits, alice ]) => {
              audits.length.should.equal(1);
              audits[0].should.be.an.Audit();
              audits[0].actorId.should.equal(alice.id);
              audits[0].details.name.should.equal('my_file1.mp4');
              audits[0].details.instanceId.should.equal('both');
            })))));

    it('should ignore unknown attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('some_random_file', Buffer.from('this is test file one'), { filename: 'some_random_file' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('other_random_file', Buffer.from('this is test file two'), { filename: 'other_random_file' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { name: 'here_is_file2.jpg', exists: false },
                  { name: 'my_file1.mp4', exists: false }
                ]);
              }))))));

    // this just ensures that we correctly pick up the attachment and save it. we verify
    // that it's been correctly processed and exports right in the .csv.zip tests below.
    it('should save client audit log attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/audits/submissions/one/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([{ name: 'audit.csv', exists: true }]);
              }))))));

    it('should create empty client audit log slots', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/audits/submissions/one/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([{ name: 'audit.csv', exists: false }]);
              }))))));

    it('should detect which attachments are expected', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.one), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/one/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([{ name: 'my_file1.mp4', exists: false }]);
              }))))));

    it('should reject if the xml changes between posts', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(201)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from('<data id="simple"><meta><instanceID>one</instanceID></meta></data>'), { filename: 'data.xml' })
            .expect(409)
            .then(({ text }) => {
              text.should.match(/different XML/i);
            })))));

    it('should take in additional attachments via additional POSTs', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
              .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
              .expect(201)
              .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
                .expect(200)
                .then(({ body }) => {
                  body.should.eql([
                    { name: 'here_is_file2.jpg', exists: true },
                    { name: 'my_file1.mp4', exists: true }
                  ]);
                })))))));

    // also tests /forms/_/submissions/_/attachments/_ return content. (mark2)
    // no point in replicating it.
    it('should successfully save attachment binary data', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
              .expect(200)
              .then(({ headers, body }) => {
                headers['content-type'].should.equal('video/mp4');
                headers['content-disposition'].should.equal('attachment; filename="my_file1.mp4"');
                body.toString('utf8').should.equal('this is test file one');
              }))))));

    it('should successfully save additionally POSTed attachment binary data', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
              .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
              .expect(201)
              .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments/here_is_file2.jpg')
                .expect(200)
                .then(({ headers, body }) => {
                  headers['content-type'].should.equal('image/jpeg');
                  headers['content-disposition'].should.equal('attachment; filename="here_is_file2.jpg"');
                  body.toString('utf8').should.equal('this is test file two');
                })))))));

    it('should accept encrypted submissions, with attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.encrypted)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('submission.xml.enc', Buffer.from('this is test file one'), { filename: 'submission.xml.enc' })
            .attach('1561432508817.jpg.enc', Buffer.from('this is test file two'), { filename: '1561432508817.jpg.enc' })
            // also attach a file that the manifest does not expect.
            .attach('extraneous.enc', Buffer.from('this is test file three'), { filename: 'extraneous.enc' })
            .attach('xml_submission_file', Buffer.from(testData.instances.encrypted.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/encrypted/submissions/uuid:dcf4a151-5088-453f-99e6-369d67828f7a.xml')
              .expect(200)
              .then(({ text }) => { text.should.equal(testData.instances.encrypted.one); }),
            asAlice.get('/v1/projects/1/forms/encrypted/submissions/uuid:dcf4a151-5088-453f-99e6-369d67828f7a/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { exists: true, name: '1561432508817.jpg.enc' },
                  { exists: true, name: 'submission.xml.enc' }
                ]);
              }),
            asAlice.get('/v1/projects/1/forms/encrypted/submissions/uuid:dcf4a151-5088-453f-99e6-369d67828f7a/attachments/submission.xml.enc')
              .expect(200)
              .then(({ body }) => { body.toString('utf8').should.equal('this is test file one'); })
          ])))));
  });

  describe('[draft] POST', () => {
    // the above tests check extensively the different cases; here we just verify plumbing
    // and correct-sorting of draft submissions.

    it('should reject notfound if there is no draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(404))));

    it('should save the submission into the form draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
            .expect(201)
            .then(({ text }) => {
              text.should.match(/upload was successful/);
            })
            .then(() => Promise.all([
              asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one')
                .expect(200)
                .then(({ body }) => {
                  body.createdAt.should.be.a.recentIsoDate();
                  should.not.exist(body.deviceId);
                }),
              asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one.xml')
                .expect(200)
                .then(({ text }) => { text.should.equal(testData.instances.simple.one); }),
              asAlice.get('/v1/projects/1/forms/simple/submissions/one')
                .expect(404)
            ]))))));

    it('should save client audit log attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/audits/draft/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201)
            .then(() => asAlice.get('/v1/projects/1/forms/audits/draft/submissions/one/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([{ name: 'audit.csv', exists: true }]);
              }))))));
  });

  describe('[draft] /test POST', () => {
    // the above tests check extensively the different cases; here we just verify plumbing
    // and correct-sorting of draft submissions.

    it('should reject notfound if there is no draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .expect(404))));

    it('should reject if the draft has been published', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft')
            .expect(200)
            .then(({ body }) => body.draftToken))
          .then((token) => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200)
            .then(() => service.post(`/v1/test/${token}/projects/1/forms/simple/draft/submission`)
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
              .expect(404))))));

    it('should reject if the draft has been deleted', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft')
            .expect(200)
            .then(({ body }) => body.draftToken))
          .then((token) => asAlice.delete('/v1/projects/1/forms/simple/draft')
            .expect(200)
            .then(() => service.post(`/v1/test/${token}/projects/1/forms/simple/draft/submission`)
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
              .expect(404))))));

    it('should reject if the key is wrong', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => service.post('/v1/test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/projects/1/forms/simple/draft/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
            .expect(404)))));

    it('should save the submission into the form draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft')
            .expect(200)
            .then(({ body }) => body.draftToken)
            .then((token) => service.post(`/v1/test/${token}/projects/1/forms/simple/draft/submission`)
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
              .expect(201)
              .then(({ text }) => {
                text.should.match(/upload was successful/);
              })
              .then(() => Promise.all([
                asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one')
                  .expect(200)
                  .then(({ body }) => {
                    body.createdAt.should.be.a.recentIsoDate();
                    should.not.exist(body.deviceId);
                  }),
                asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one.xml')
                  .expect(200)
                  .then(({ text }) => { text.should.equal(testData.instances.simple.one); }),
                asAlice.get('/v1/projects/1/forms/simple/submissions/one')
                  .expect(404)
              ])))))));
  });
});

describe('api: /forms/:id/submissions', () => {
  describe('POST', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/nonexistent/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(404))));

    it('should reject if the user cannot submit', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(403))));

    it('should reject if the form is not taking submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.patch('/v1/projects/1/forms/simple')
          .send({ state: 'closed' })
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(409)))));

    it('should reject if the submission body is not valid xml', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send('<aoeu')
          .set('Content-Type', 'text/xml')
          .expect(400)
          .then(({ body }) => {
            body.code.should.equal(400.2);
            body.details.field.should.match(/form ID xml attribute/i);
          }))));

    it('should reject if the form ids do not match', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send('<data id="simple3"><meta><instanceID>three</instanceID></meta></data>')
          .set('Content-Type', 'text/xml')
          .expect(400)
          .then(({ body }) => {
            body.code.should.equal(400.8);
            body.details.reason.should.match(/did not match.*url/i);
          }))));

    it('should reject if the form is not taking submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.patch('/v1/projects/1/forms/simple')
          .send({ state: 'closed' })
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(409)
            .then(({ body }) => {
              body.code.should.equal(409.2);
              body.message.should.match(/not currently accepting submissions/);
            })))));

    it('should reject if the submission version does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(Buffer.from('<data id="simple" version="-1"><meta><instanceID>one</instanceID></meta></data>'))
          .set('Content-Type', 'text/xml')
          .expect(404))));

    it('should submit if all details are provided', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(({ body }) => {
            body.should.be.a.Submission();
            body.createdAt.should.be.a.recentIsoDate();
            body.submitterId.should.equal(5);
          }))));

    it('should accept a submission for an old form version', testService((service, { simply, SubmissionDef, FormDef }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=three')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send('<data id="simple" version="two"><orx:meta><orx:instanceID>one</orx:instanceID></orx:meta></data>')
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
            .expect(200))
          // the submission worked, that's good. the rest of this checks that it went
          // to the correct place.
          .then(() => SubmissionDef.getCurrentByIds(1, 'simple', 'one', false))
          .then((o) => o.get())
          .then(({ formDefId }) => simply.getOneWhere('form_defs', { id: formDefId }, FormDef))
          .then((o) => o.get())
          .then((formDef) => {
            formDef.version.should.equal('two');
          }))));

    it('should create expected attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { name: 'here_is_file2.jpg', exists: false },
                  { name: 'my_file1.mp4', exists: false }
                ]);
              }))))));

    it('should store the correct formdef and actor ids', testService((service, { db }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => Promise.all([
            asAlice.get('/v1/users/current').then(({ body }) => body.id),
            db.select('formDefId', 'submitterId').from('submission_defs')
          ]))
          .then(([ aliceId, submissions ]) => {
            submissions.length.should.equal(1);
            submissions[0].submitterId.should.equal(aliceId);
            return db.select('xml').from('form_defs').where({ id: submissions[0].formDefId })
              .then(([ def ]) => {
                def.xml.should.equal(testData.forms.simple);
              });
          }))));

    it('should accept encrypted submissions, with attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.encrypted)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/encrypted/submissions/uuid:dcf4a151-5088-453f-99e6-369d67828f7a.xml')
              .expect(200)
              .then(({ text }) => { text.should.equal(testData.instances.encrypted.one); }),
            asAlice.get('/v1/projects/1/forms/encrypted/submissions/uuid:dcf4a151-5088-453f-99e6-369d67828f7a/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { exists: false, name: '1561432508817.jpg.enc' },
                  { exists: false, name: 'submission.xml.enc' }
                ]);
              })
          ])))));
  });

  describe('[draft] POST', () => {
    it('should return notfound if there is no draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(404))));

    it('should accept submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200)
            .then(({ body }) => {
              body.should.be.a.Submission();
              body.createdAt.should.be.a.recentIsoDate();
              body.submitterId.should.equal(5);
            })))));

    it('should accept even if the form is not taking submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.patch('/v1/projects/1/forms/simple')
          .send({ state: 'closed' })
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200)
            .then(({ body }) => {
              body.should.be.a.Submission();
              body.createdAt.should.be.a.recentIsoDate();
              body.submitterId.should.equal(5);
            }))
          .then(() => Promise.all([
            asAlice.get('/v1/projects/1/forms/simple/submissions/one').expect(404),
            asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one').expect(200)
          ])))));
  });

  describe('.csv.zip GET', () => {
    // NOTE: tests related to decryption of .csv.zip export are located in test/integration/other/encryption.js

    it('should return a zipfile with the relevant headers', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip')
          .expect(200)
          .then(({ headers }) => {
            headers['content-disposition'].should.equal('attachment; filename="simple.zip"');
            headers['content-type'].should.equal('application/zip');
          }))));

    it('should return the csv header even if there is no data', testService((service) =>
      service.login('alice', (asAlice) => new Promise((done) =>
        zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
          result.filenames.should.eql([ 'simple.csv' ]);
          result['simple.csv'].should.equal('SubmissionDate,meta-instanceID,name,age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status\n');
          done();
        })))));

    it('should return a zipfile with the relevant data', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.three)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => new Promise((done) =>
            zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
              result.filenames.should.eql([ 'simple.csv' ]);
              result['simple.csv'].should.be.a.SimpleCsv();
              done();
            }))))));

    it('should include all repeat rows @slow', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(`
<?xml version="1.0"?>
<h:html xmlns="http://www.w3.org/2002/xforms" xmlns:ev="http://www.w3.org/2001/xml-events" xmlns:h="http://www.w3.org/1999/xhtml" xmlns:jr="http://openrosa.org/javarosa" xmlns:odk="http://www.opendatakit.org/xforms" xmlns:orx="http://openrosa.org/xforms" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<h:head><h:title>single-repeat-1-instance-10qs</h:title><model odk:xforms-version="1.0.0">
<instance><data id="single-repeat-1-instance-10qs"><q1/><q2/><q3/><q4/><q5/><q6/><q7/><q8/><q9/><q10/><q11/><q12/><q13/><q14/><q15/><q16/><q17/><q18/><q19/><q20/><q21/><repeat jr:template=""><q22/><q23/><q24/><q25/><q26/><q27/><q28/><q29/><q30/><q31/><q32/><q33/><q34/><q35/><q36/><q37/><q38/><q39/><q40/><q41/></repeat><repeat><q22/><q23/><q24/><q25/><q26/><q27/><q28/><q29/><q30/><q31/><q32/><q33/><q34/><q35/><q36/><q37/><q38/><q39/><q40/><q41/></repeat><q42/><q43/><q44/><q45/><q46/><q47/><q48/><q49/><q50/><meta><instanceID/></meta></data></instance>
<bind nodeset="/data/q1" type="string"/><bind nodeset="/data/q2" type="string"/><bind nodeset="/data/q3" type="string"/><bind nodeset="/data/q4" type="string"/><bind nodeset="/data/q5" type="string"/><bind nodeset="/data/q6" type="string"/><bind nodeset="/data/q7" type="string"/><bind nodeset="/data/q8" type="string"/><bind nodeset="/data/q9" type="string"/><bind nodeset="/data/q10" type="string"/><bind nodeset="/data/q11" type="string"/><bind nodeset="/data/q12" type="string"/><bind nodeset="/data/q13" type="string"/><bind nodeset="/data/q14" type="string"/><bind nodeset="/data/q15" type="string"/><bind nodeset="/data/q16" type="string"/><bind nodeset="/data/q17" type="string"/><bind nodeset="/data/q18" type="string"/><bind nodeset="/data/q19" type="string"/><bind nodeset="/data/q20" type="string"/><bind nodeset="/data/q21" type="string"/><bind nodeset="/data/repeat/q22" type="string"/><bind nodeset="/data/repeat/q23" type="string"/><bind nodeset="/data/repeat/q24" type="string"/><bind nodeset="/data/repeat/q25" type="string"/><bind nodeset="/data/repeat/q26" type="string"/><bind nodeset="/data/repeat/q27" type="string"/><bind nodeset="/data/repeat/q28" type="string"/><bind nodeset="/data/repeat/q29" type="string"/><bind nodeset="/data/repeat/q30" type="string"/><bind nodeset="/data/repeat/q31" type="string"/><bind nodeset="/data/repeat/q32" type="string"/><bind nodeset="/data/repeat/q33" type="string"/><bind nodeset="/data/repeat/q34" type="string"/><bind nodeset="/data/repeat/q35" type="string"/><bind nodeset="/data/repeat/q36" type="string"/><bind nodeset="/data/repeat/q37" type="string"/><bind nodeset="/data/repeat/q38" type="string"/><bind nodeset="/data/repeat/q39" type="string"/><bind nodeset="/data/repeat/q40" type="string"/><bind nodeset="/data/repeat/q41" type="string"/><bind nodeset="/data/q42" type="string"/><bind nodeset="/data/q43" type="string"/><bind nodeset="/data/q44" type="string"/><bind nodeset="/data/q45" type="string"/><bind nodeset="/data/q46" type="string"/><bind nodeset="/data/q47" type="string"/><bind nodeset="/data/q48" type="string"/><bind nodeset="/data/q49" type="string"/><bind nodeset="/data/q50" type="string"/><bind jr:preload="uid" nodeset="/data/meta/instanceID" readonly="true()" type="string"/></model></h:head>
<h:body><input ref="/data/q1"><label>Q1</label></input><input ref="/data/q2"><label>Q2</label></input><input ref="/data/q3"><label>Q3</label></input><input ref="/data/q4"><label>Q4</label></input><input ref="/data/q5"><label>Q5</label></input><input ref="/data/q6"><label>Q6</label></input><input ref="/data/q7"><label>Q7</label></input><input ref="/data/q8"><label>Q8</label></input><input ref="/data/q9"><label>Q9</label></input><input ref="/data/q10"><label>Q10</label></input><input ref="/data/q11"><label>Q11</label></input><input ref="/data/q12"><label>Q12</label></input><input ref="/data/q13"><label>Q13</label></input><input ref="/data/q14"><label>Q14</label></input><input ref="/data/q15"><label>Q15</label></input><input ref="/data/q16"><label>Q16</label></input><input ref="/data/q17"><label>Q17</label></input><input ref="/data/q18"><label>Q18</label></input><input ref="/data/q19"><label>Q19</label></input><input ref="/data/q20"><label>Q20</label></input><input ref="/data/q21"><label>Q21</label></input><group ref="/data/repeat"><label>Repeat</label><repeat nodeset="/data/repeat"><input ref="/data/repeat/q22"><label>Q22</label></input><input ref="/data/repeat/q23"><label>Q23</label></input><input ref="/data/repeat/q24"><label>Q24</label></input><input ref="/data/repeat/q25"><label>Q25</label></input><input ref="/data/repeat/q26"><label>Q26</label></input><input ref="/data/repeat/q27"><label>Q27</label></input><input ref="/data/repeat/q28"><label>Q28</label></input><input ref="/data/repeat/q29"><label>Q29</label></input><input ref="/data/repeat/q30"><label>Q30</label></input><input ref="/data/repeat/q31"><label>Q31</label></input><input ref="/data/repeat/q32"><label>Q32</label></input><input ref="/data/repeat/q33"><label>Q33</label></input><input ref="/data/repeat/q34"><label>Q34</label></input><input ref="/data/repeat/q35"><label>Q35</label></input><input ref="/data/repeat/q36"><label>Q36</label></input><input ref="/data/repeat/q37"><label>Q37</label></input><input ref="/data/repeat/q38"><label>Q38</label></input><input ref="/data/repeat/q39"><label>Q39</label></input><input ref="/data/repeat/q40"><label>Q40</label></input><input ref="/data/repeat/q41"><label>Q41</label></input></repeat></group><input ref="/data/q42"><label>Q42</label></input><input ref="/data/q43"><label>Q43</label></input><input ref="/data/q44"><label>Q44</label></input><input ref="/data/q45"><label>Q45</label></input><input ref="/data/q46"><label>Q46</label></input><input ref="/data/q47"><label>Q47</label></input><input ref="/data/q48"><label>Q48</label></input><input ref="/data/q49"><label>Q49</label></input><input ref="/data/q50"><label>Q50</label></input></h:body></h:html>`)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => Promise.all((new Array(50)).fill(null).map(_ =>
            asAlice.post('/v1/projects/1/forms/single-repeat-1-instance-10qs/submissions')
              .send(`<data id="single-repeat-1-instance-10qs">
  <meta><instanceID>${uuid()}</instanceID></meta>
  ${[ 1, 2, 3, 4, 5, 6, 7, 8, 9 ].map((q) => `<q${q}>${uuid()}</q${q}>`).join('')}
  <repeat>${[ 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 ].map((q) => `<q${q}>${uuid()}</q${q}>`).join('')}</repeat>
  ${[ 42, 43, 44, 45, 46, 47, 48, 49, 50 ].map((q) => `<q${q}>${uuid()}</q${q}>`).join('')}
  </data>`)
              .set('Content-Type', 'text/xml')
              .expect(200)))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/single-repeat-1-instance-10qs/submissions.csv.zip'), (result) => {
                result.filenames.should.eql([ 'single-repeat-1-instance-10qs.csv', 'single-repeat-1-instance-10qs-repeat.csv' ]);
                result['single-repeat-1-instance-10qs.csv'].split('\n').length.should.equal(52);
                result['single-repeat-1-instance-10qs-repeat.csv'].split('\n').length.should.equal(52);
                done();
              })))))));

    it('should not include data from other forms', testService((service) =>
      service.login('alice', (asAlice) => Promise.all([
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200)),
        asAlice.post('/v1/projects/1/forms/withrepeat/submissions')
          .send(testData.instances.withrepeat.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/withrepeat/submissions')
            .send(testData.instances.withrepeat.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
      ])
        .then(() => new Promise((done) =>
          zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
            result.filenames.should.eql([ 'simple.csv' ]);
            const csv = result['simple.csv'].split('\n').map((row) => row.split(','));
            csv.length.should.equal(4); // header + 2 data rows + newline
            csv[0].should.eql([ 'SubmissionDate', 'meta-instanceID', 'name', 'age', 'KEY', 'SubmitterID', 'SubmitterName', 'AttachmentsPresent', 'AttachmentsExpected', 'Status' ]);
            csv[1].shift().should.be.an.recentIsoDate();
            csv[1].should.eql([ 'two','Bob','34','two','5','Alice','0','0' ]);
            csv[2].shift().should.be.an.recentIsoDate();
            csv[2].should.eql([ 'one','Alice','30','one','5','Alice','0','0' ]);
            csv[3].should.eql([ '' ]);
            done();
          }))))));

    it('should return a submitter-filtered zipfile with the relevant data', testService((service) =>
      service.login('alice', (asAlice) =>
        service.login('bob', (asBob) =>
          asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asBob.post('/v1/projects/1/forms/simple/submissions')
              .send(testData.instances.simple.two)
              .set('Content-Type', 'text/xml')
              .expect(200))
            .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
              .send(testData.instances.simple.three)
              .set('Content-Type', 'text/xml')
              .expect(200))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip?$filter=__system/submitterId eq 5'), (result) => {
                result.filenames.should.eql([ 'simple.csv' ]);
                const lines = result['simple.csv'].split('\n');
                lines.length.should.equal(4);
                lines[1].endsWith(',three,Chelsea,38,three,5,Alice,0,0').should.equal(true);
                lines[2].endsWith(',one,Alice,30,one,5,Alice,0,0').should.equal(true);
                done();
              })))))));

    it('should return a submissionDate-filtered zipfile with the relevant data', testService((service, { db }) =>
      service.login('alice', (asAlice) =>
        service.login('bob', (asBob) =>
          asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => db.update({ createdAt: new Date('2010-06-01') }).into('submissions'))
            .then(() => asBob.post('/v1/projects/1/forms/simple/submissions')
              .send(testData.instances.simple.two)
              .set('Content-Type', 'text/xml')
              .expect(200))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip?$filter=year(__system/submissionDate) eq 2010'), (result) => {
                result.filenames.should.eql([ 'simple.csv' ]);
                const lines = result['simple.csv'].split('\n');
                lines.length.should.equal(3);
                lines[1].endsWith(',one,Alice,30,one,5,Alice,0,0').should.equal(true);
                done();
              })))))));

    it('should return a zipfile with the relevant attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .expect(201)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
              .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
              .expect(201))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/binaryType/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([
                  'binaryType.csv',
                  'media/my_file1.mp4',
                  'media/here_is_file2.jpg'
                ]);

                result['media/my_file1.mp4'].should.equal('this is test file one');
                result['media/here_is_file2.jpg'].should.equal('this is test file two');

                // we also check the csv for the sake of verifying the attachments counts.
                const csv = result['binaryType.csv'].split('\n');
                csv[0].should.equal('SubmissionDate,meta-instanceID,file1,file2,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status');
                csv[1].should.endWith(',both,my_file1.mp4,here_is_file2.jpg,both,5,Alice,2,2');
                csv.length.should.equal(3); // newline at end

                done();
              })))))));

    it('should filter attachments by the query', testService((service) =>
      service.login('alice', (asAlice) =>
        service.login('bob', (asBob) =>
          asAlice.post('/v1/projects/1/forms?publish=true')
            .set('Content-Type', 'application/xml')
            .send(testData.forms.binaryType)
            .expect(200)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.one), { filename: 'data.xml' })
              .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
              .expect(201)
              .then(() => asBob.post('/v1/projects/1/submission')
                .set('X-OpenRosa-Version', '1.0')
                .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.two), { filename: 'data.xml' })
                .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
                .expect(201))
              .then(() => new Promise((done) =>
                zipStreamToFiles(asAlice.get('/v1/projects/1/forms/binaryType/submissions.csv.zip?$filter=__system/submitterId eq 5'), (result) => {
                  result.filenames.should.eql([
                    'binaryType.csv',
                    'media/my_file1.mp4'
                  ]);
                  done();
                }))))))));

    it('should skip attachments if ?attachments=false is given', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .expect(201)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
              .attach('here_is_file2.jpg', Buffer.from('this is test file two'), { filename: 'here_is_file2.jpg' })
              .expect(201))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/binaryType/submissions.csv.zip?attachments=false'), (result) => {
                result.filenames.should.containDeep([ 'binaryType.csv' ]);

                should.not.exist(result['media/my_file1.mp4']);
                should.not.exist(result['media/here_is_file2.jpg']);

                done();
              })))))));

    it('should give the appropriate filename if ?attachments=false is given', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .expect(201))
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions.csv.zip?attachments=false')
              .expect(200)
              .then(({ headers }) => {
                headers['content-disposition'].should.equal('attachment; filename="binaryType.csv.zip"');
              })))));

    it('should properly count present attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('xml_submission_file', Buffer.from(testData.instances.binaryType.both), { filename: 'data.xml' })
            .attach('my_file1.mp4', Buffer.from('this is test file one'), { filename: 'my_file1.mp4' })
            .expect(201)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/binaryType/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([
                  'binaryType.csv',
                  'media/my_file1.mp4'
                ]);

                // we also check the csv for the sake of verifying the attachments counts.
                const csv = result['binaryType.csv'].split('\n');
                csv[0].should.equal('SubmissionDate,meta-instanceID,file1,file2,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status');
                csv[1].should.endWith(',both,my_file1.mp4,here_is_file2.jpg,both,5,Alice,1,2');
                csv.length.should.equal(3); // newline at end

                done();
              })))))));

    it('should return worker-processed consolidated client audit log attachments', testService((service, container) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('log.csv', createReadStream(appRoot + '/test/data/audit2.csv'), { filename: 'log.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.two), { filename: 'data.xml' })
            .expect(201))
          .then(() => exhaust(container))
          .then(() => new Promise((done) =>
            zipStreamToFiles(asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip'), (result) => {
              result.filenames.should.containDeep([
                'audits.csv',
                'media/audit.csv',
                'media/log.csv',
                'audits - audit.csv'
              ]);

              result['audits - audit.csv'].should.equal(`event,node,start,end,latitude,longitude,accuracy,old-value,new-value
a,/data/a,2000-01-01T00:01,2000-01-01T00:02,1,2,3,aa,bb
b,/data/b,2000-01-01T00:02,2000-01-01T00:03,4,5,6,cc,dd
c,/data/c,2000-01-01T00:03,2000-01-01T00:04,7,8,9,ee,ff
d,/data/d,2000-01-01T00:10,,10,11,12,gg,
e,/data/e,2000-01-01T00:11,,,,,hh,ii
f,/data/f,2000-01-01T00:04,2000-01-01T00:05,-1,-2,,aa,bb
g,/data/g,2000-01-01T00:05,2000-01-01T00:06,-3,-4,,cc,dd
h,/data/h,2000-01-01T00:06,2000-01-01T00:07,-5,-6,,ee,ff
`);

              done();
            })))
          .then(() => container.simply.countWhere('client_audits')
            .then((count) => { count.should.equal(8); })))));

    it('should return adhoc-processed consolidated client audit log attachments', testService((service, container) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('log.csv', createReadStream(appRoot + '/test/data/audit2.csv'), { filename: 'log.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.two), { filename: 'data.xml' })
            .expect(201))
          .then(() => new Promise((done) =>
            zipStreamToFiles(asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip'), (result) => {
              result.filenames.should.containDeep([
                'audits.csv',
                'media/audit.csv',
                'media/log.csv',
                'audits - audit.csv'
              ]);

              result['audits - audit.csv'].should.equal(`event,node,start,end,latitude,longitude,accuracy,old-value,new-value
a,/data/a,2000-01-01T00:01,2000-01-01T00:02,1,2,3,aa,bb
b,/data/b,2000-01-01T00:02,2000-01-01T00:03,4,5,6,cc,dd
c,/data/c,2000-01-01T00:03,2000-01-01T00:04,7,8,9,ee,ff
d,/data/d,2000-01-01T00:10,,10,11,12,gg,
e,/data/e,2000-01-01T00:11,,,,,hh,ii
f,/data/f,2000-01-01T00:04,2000-01-01T00:05,-1,-2,,aa,bb
g,/data/g,2000-01-01T00:05,2000-01-01T00:06,-3,-4,,cc,dd
h,/data/h,2000-01-01T00:06,2000-01-01T00:07,-5,-6,,ee,ff
`);

              done();
            }))))));

    it('should return adhoc-processed consolidated client audit log attachments', testService((service, container) =>
      service.login('alice', (asAlice) =>
        service.login('bob', (asBob) =>
          asAlice.post('/v1/projects/1/forms?publish=true')
            .set('Content-Type', 'application/xml')
            .send(testData.forms.clientAudits)
            .expect(200)
            .then(() => asAlice.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
              .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
              .expect(201))
            .then(() => asBob.post('/v1/projects/1/submission')
              .set('X-OpenRosa-Version', '1.0')
              .attach('log.csv', createReadStream(appRoot + '/test/data/audit2.csv'), { filename: 'log.csv' })
              .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.two), { filename: 'data.xml' })
              .expect(201))
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip?$filter=__system/submitterId eq 5'), (result) => {
                result.filenames.should.containDeep([
                  'audits.csv',
                  'media/audit.csv',
                  'audits - audit.csv'
                ]);

                result['audits - audit.csv'].should.equal(`event,node,start,end,latitude,longitude,accuracy,old-value,new-value
a,/data/a,2000-01-01T00:01,2000-01-01T00:02,1,2,3,aa,bb
b,/data/b,2000-01-01T00:02,2000-01-01T00:03,4,5,6,cc,dd
c,/data/c,2000-01-01T00:03,2000-01-01T00:04,7,8,9,ee,ff
d,/data/d,2000-01-01T00:10,,10,11,12,gg,
e,/data/e,2000-01-01T00:11,,,,,hh,ii
`);

                done();
              })))))));

    it('should return the latest attached audit log after openrosa replace', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit2.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([
                  'audits.csv',
                  'media/audit.csv',
                  'audits - audit.csv'
                ]);

                result['audits - audit.csv'].should.equal(`event,node,start,end,latitude,longitude,accuracy,old-value,new-value
f,/data/f,2000-01-01T00:04,2000-01-01T00:05,-1,-2,,aa,bb
g,/data/g,2000-01-01T00:05,2000-01-01T00:06,-3,-4,,cc,dd
h,/data/h,2000-01-01T00:06,2000-01-01T00:07,-5,-6,,ee,ff
`);

                done();
              })))))));

    it('should return the latest attached audit log after REST replace', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.clientAudits)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/submission')
            .set('X-OpenRosa-Version', '1.0')
            .attach('audit.csv', createReadStream(appRoot + '/test/data/audit.csv'), { filename: 'audit.csv' })
            .attach('xml_submission_file', Buffer.from(testData.instances.clientAudits.one), { filename: 'data.xml' })
            .expect(201))
          .then(() => asAlice.post('/v1/projects/1/forms/audits/submissions/one/attachments/audit.csv')
            .set('Content-Type', 'text/csv')
            .send(readFileSync(appRoot + '/test/data/audit2.csv'))
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/audits/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([
                  'audits.csv',
                  'media/audit.csv',
                  'audits - audit.csv'
                ]);

                result['audits - audit.csv'].should.equal(`event,node,start,end,latitude,longitude,accuracy,old-value,new-value
f,/data/f,2000-01-01T00:04,2000-01-01T00:05,-1,-2,,aa,bb
g,/data/g,2000-01-01T00:05,2000-01-01T00:06,-3,-4,,cc,dd
h,/data/h,2000-01-01T00:06,2000-01-01T00:07,-5,-6,,ee,ff
`);

                done();
              })))))));
  });

  describe('.csv GET', () => {
    // NOTE: tests related to decryption of .csv.zip export are located in test/integration/other/encryption.js

    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nope/submissions.csv')
          .expect(404))));

    it('should reject if the user cannot get submissions', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.get('/v1/projects/1/forms/simple/submissions.csv')
          .expect(403))));

    it('should return a csv with the relevant headers', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions.csv')
          .expect(200)
          .then(({ headers }) => {
            headers['content-disposition'].should.equal('attachment; filename="simple.csv"');
            headers['content-type'].should.equal('text/csv; charset=utf-8');
          }))));

    it('should return the root csv table', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.three)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions.csv')
            .expect(200)
            .then(({ text }) => { text.should.be.a.SimpleCsv(); })))));

    it('should return only the root csv table given repeats', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/withrepeat/submissions')
          .send(testData.instances.withrepeat.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/withrepeat/submissions')
            .send(testData.instances.withrepeat.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/withrepeat/submissions')
            .send(testData.instances.withrepeat.three)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/withrepeat/submissions.csv')
            .expect(200)
            .then(({ text }) => {
              const rows = text.split('\n');
              rows.length.should.equal(5);
              rows[0].should.equal('SubmissionDate,meta-instanceID,name,age,children-child-name,children-child-age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status');
              // (need to drop the iso date)
              rows[1].slice(24).should.equal(',three,Chelsea,38,,,three,5,Alice,0,0');
              rows[2].slice(24).should.equal(',two,Bob,34,,,two,5,Alice,0,0');
              rows[3].slice(24).should.equal(',one,Alice,30,,,one,5,Alice,0,0');
            })))));
  });

  describe('[draft] .csv.zip', () => {
    it('should return notfound if there is no draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip')
          .expect(404))));

    it('should return draft submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([ 'simple.csv' ]);

                const csv = result['simple.csv'].split('\n').map((row) => row.split(','));
                csv.length.should.equal(3); // header + data row + newline
                csv[0].should.eql([ 'SubmissionDate', 'meta-instanceID', 'name', 'age', 'KEY', 'SubmitterID', 'SubmitterName', 'AttachmentsPresent', 'AttachmentsExpected', 'Status' ]);
                csv[1].shift().should.be.an.recentIsoDate();
                csv[1].should.eql([ 'one','Alice','30','one','5','Alice','0','0' ]);

                done();
              })))))));

    it('should not include draft submissions in nondraft csvzip', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([ 'simple.csv' ]);

                result['simple.csv'].should.equal('SubmissionDate,meta-instanceID,name,age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status\n');
                done();
              })))))));

    it('should not carry draft submissions forward to the published version upon publish', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([ 'simple.csv' ]);

                result['simple.csv'].should.equal('SubmissionDate,meta-instanceID,name,age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status\n');
                done();
              })))))));

    it('should not carry over drafts when a draft is replaced', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([ 'simple.csv' ]);

                result['simple.csv'].should.equal('SubmissionDate,meta-instanceID,name,age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status\n');
                done();
              })))))));

    it('should not resurface drafts when a draft is recreated', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions.csv.zip')
            .expect(200)
            .then(() => new Promise((done) =>
              zipStreamToFiles(asAlice.get('/v1/projects/1/forms/simple/submissions.csv.zip'), (result) => {
                result.filenames.should.containDeep([ 'simple.csv' ]);

                result['simple.csv'].should.equal('SubmissionDate,meta-instanceID,name,age,KEY,SubmitterID,SubmitterName,AttachmentsPresent,AttachmentsExpected,Status\n');
                done();
              })))))));
  });

  describe('GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions').expect(404))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.get('/v1/projects/1/forms/simple/submissions').expect(403))));

    it('should happily return given no submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions')
          .expect(200)
          .then(({ body }) => {
            body.should.eql([]);
          }))));

    it('should return a list of submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions')
            .expect(200)
            .then(({ body }) => {
              body.forEach((submission) => submission.should.be.a.Submission());
              body.map((submission) => submission.instanceId).should.eql([ 'two', 'one' ]);
            })))));

    it('should list with extended metadata if requested', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions')
            .set('X-Extended-Metadata', 'true')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.an.ExtendedSubmission();
              body[0].submitter.displayName.should.equal('Alice');
            })))));
  });

  describe('[draft] GET', () => {
    it('should return notfound if the draft does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/draft/submissions').expect(404))));

    it('should return a list of submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions')
            .expect(200)
            .then(({ body }) => {
              body.forEach((submission) => submission.should.be.a.Submission());
              body.map((submission) => submission.instanceId).should.eql([ 'two', 'one' ]);
            })))));

    it('should not include draft submissions non-draft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not carry draft submissions forward to the published version upon publish', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not carry over drafts when a draft is replaced', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not resurface drafts when a draft is recreated', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));
  });

  describe('/keys GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions/keys').expect(404))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.get('/v1/projects/1/forms/simple/submissions/keys').expect(403))));

    it('should return an empty array if encryption is not being used', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.should.eql([]);
            })))));

    // a bit of a compound test, since there is no way as of time of writing to verify
    // that the form def key parsing and storage works. so this test catches form /and/
    // submission key handling.
    it('should return a self-managed key if it is used', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.a.Key();
              body[0].public.should.equal('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYh7bSui/0xppQ+J3i5xghfao+559Rqg9X0xNbdMEsW35CzYUfmC8sOzeeUiE4pG7HIEUmiJal+mo70UMDUlywXj9z053n0g6MmtLlUyBw0ZGhEZWHsfBxPQixdzY/c5i7sh0dFzWVBZ7UrqBc2qjRFUYxeXqHsAxSPClTH1nW47Mr2h4juBLC7tBNZA3biZA/XTPt//hAuzv1d6MGiF3vQJXvFTNdfsh6Ckq4KXUsAv+07cLtON4KjrKhqsVNNGbFssTUHVL4A9N3gsuRGt329LHOKBxQUGEnhMM2MEtvk4kaVQrgCqpk1pMU/4HlFtRjOoKdAIuzzxIl56gNdRUQIDAQAB');
            })))));

    it('should return multiple self-managed keys if they are used', testService((service, { db, Project, FormDef, FormPartial }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => Promise.all([
            Project.getById(1).then((o) => o.get())
              .then((project) => project.getFormByXmlFormId('encrypted')).then((o) => o.get()),
            FormPartial.fromXml(testData.forms.encrypted
              .replace(/PublicKey="[a-z0-9+\/]+"/i, 'PublicKey="keytwo"')
              .replace('working3', 'working4'))
          ]))
          .then(([ form, partial ]) => partial.createVersion(form, true))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.two
              .replace(/EncryptedKey.*EncryptedKey/, 'EncryptedKey>keytwo</base64EncryptedKey')
              .replace('working3', 'working4'))
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(2);
              body[0].should.be.a.Key();
              body[0].public.should.equal('keytwo');
              body[1].should.be.a.Key();
              body[1].public.should.equal('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYh7bSui/0xppQ+J3i5xghfao+559Rqg9X0xNbdMEsW35CzYUfmC8sOzeeUiE4pG7HIEUmiJal+mo70UMDUlywXj9z053n0g6MmtLlUyBw0ZGhEZWHsfBxPQixdzY/c5i7sh0dFzWVBZ7UrqBc2qjRFUYxeXqHsAxSPClTH1nW47Mr2h4juBLC7tBNZA3biZA/XTPt//hAuzv1d6MGiF3vQJXvFTNdfsh6Ckq4KXUsAv+07cLtON4KjrKhqsVNNGbFssTUHVL4A9N3gsuRGt329LHOKBxQUGEnhMM2MEtvk4kaVQrgCqpk1pMU/4HlFtRjOoKdAIuzzxIl56gNdRUQIDAQAB');
            })))));

    it('should not return unused keys', testService((service, { Project, FormDef, FormPartial }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => Promise.all([
            Project.getById(1).then((o) => o.get())
              .then((project) => project.getFormByXmlFormId('encrypted')).then((o) => o.get()),
            FormPartial.fromXml(testData.forms.encrypted
              .replace(/PublicKey="[a-z0-9+\/]+"/i, 'PublicKey="keytwo"')
              .replace('working3', 'working4'))
          ]))
          .then(([ form, partial ]) => partial.createVersion(form))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.a.Key();
              body[0].public.should.equal('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYh7bSui/0xppQ+J3i5xghfao+559Rqg9X0xNbdMEsW35CzYUfmC8sOzeeUiE4pG7HIEUmiJal+mo70UMDUlywXj9z053n0g6MmtLlUyBw0ZGhEZWHsfBxPQixdzY/c5i7sh0dFzWVBZ7UrqBc2qjRFUYxeXqHsAxSPClTH1nW47Mr2h4juBLC7tBNZA3biZA/XTPt//hAuzv1d6MGiF3vQJXvFTNdfsh6Ckq4KXUsAv+07cLtON4KjrKhqsVNNGbFssTUHVL4A9N3gsuRGt329LHOKBxQUGEnhMM2MEtvk4kaVQrgCqpk1pMU/4HlFtRjOoKdAIuzzxIl56gNdRUQIDAQAB');
            })))));

    it('should return managed keys, with hint', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/key')
          .send({ passphrase: 'supersecret', hint: 'it is a secret' })
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple')
            .expect(200)
            .then(({ body }) => body.version))
          .then((version) => asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.encrypted.one
              .replace('id="encrypted" version="working3"', `id="simple" version="${version}"`))
            .set('Content-Type', 'application/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.a.Key();
              body[0].managed.should.equal(true);
              body[0].hint.should.equal('it is a secret');
            })))));

    it('should not return a key more than once', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/submissions')
            .send(testData.instances.encrypted.two)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.a.Key();
              body[0].public.should.equal('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYh7bSui/0xppQ+J3i5xghfao+559Rqg9X0xNbdMEsW35CzYUfmC8sOzeeUiE4pG7HIEUmiJal+mo70UMDUlywXj9z053n0g6MmtLlUyBw0ZGhEZWHsfBxPQixdzY/c5i7sh0dFzWVBZ7UrqBc2qjRFUYxeXqHsAxSPClTH1nW47Mr2h4juBLC7tBNZA3biZA/XTPt//hAuzv1d6MGiF3vQJXvFTNdfsh6Ckq4KXUsAv+07cLtON4KjrKhqsVNNGbFssTUHVL4A9N3gsuRGt329LHOKBxQUGEnhMM2MEtvk4kaVQrgCqpk1pMU/4HlFtRjOoKdAIuzzxIl56gNdRUQIDAQAB');
            })))));

    // TODO: when submission versioning exists, this needs to be tested.
    //it('should not return a key attached to an outdated submission', testService((service) =>
  });

  describe('/submitters GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions/submitters').expect(404))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.get('/v1/projects/1/forms/simple/submissions/submitters').expect(403))));

    it('should return an empty array if there are no submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions/submitters')
          .expect(200)
          .then(({ body }) => { body.should.eql([]); }))));

    it('should return all submitters once', testService((service) =>
      service.login('alice', (asAlice) =>
        service.login('bob', (asBob) =>
          asAlice.post('/v1/projects/1/forms/simple/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asBob.post('/v1/projects/1/forms/simple/submissions')
              .send(testData.instances.simple.two)
              .set('Content-Type', 'text/xml')
              .expect(200))
            .then(() => asAlice.post('/v1/projects/1/forms/simple/submissions')
              .send(testData.instances.simple.three)
              .set('Content-Type', 'text/xml')
              .expect(200))
            .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/submitters')
              .expect(200)
              .then(({ body }) => {
                body.length.should.equal(2);
                body[0].displayName.should.equal('Alice');
                body[1].displayName.should.equal('Bob');
              }))))));
  });

  describe('[draft] /keys GET', () => {
    it('should return notfound if the draft does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions/draft/keys').expect(404))));

    it('should return draft-used keys', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/draft/submissions/keys')
            .expect(200)
            .then(({ body }) => {
              body.length.should.equal(1);
              body[0].should.be.a.Key();
              body[0].public.should.equal('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyYh7bSui/0xppQ+J3i5xghfao+559Rqg9X0xNbdMEsW35CzYUfmC8sOzeeUiE4pG7HIEUmiJal+mo70UMDUlywXj9z053n0g6MmtLlUyBw0ZGhEZWHsfBxPQixdzY/c5i7sh0dFzWVBZ7UrqBc2qjRFUYxeXqHsAxSPClTH1nW47Mr2h4juBLC7tBNZA3biZA/XTPt//hAuzv1d6MGiF3vQJXvFTNdfsh6Ckq4KXUsAv+07cLtON4KjrKhqsVNNGbFssTUHVL4A9N3gsuRGt329LHOKBxQUGEnhMM2MEtvk4kaVQrgCqpk1pMU/4HlFtRjOoKdAIuzzxIl56gNdRUQIDAQAB');
            })))));

    it('should not include draft keys nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not carry draft keys forward to the published version upon publish', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/submissions/keys')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not carry over draft keys when a draft is replaced', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/draft/submissions/keys')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));

    it('should not resurface draft keys when a draft is recreated', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .send(testData.forms.encrypted)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/submissions')
            .send(testData.instances.encrypted.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/encrypted/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/encrypted/draft/submissions/keys')
            .expect(200)
            .then(({ body }) => { body.should.eql([]); })))));
  });

  describe('/:instanceId.xml GET', () => {
    it('should return submission details', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
            .expect(200)
            .then(({ header, text }) => {
              header['content-type'].should.equal('application/xml; charset=utf-8');
              text.should.equal(testData.instances.simple.one);
            })))));
  });

  describe('[draft] /:instanceId.xml GET', () => {
    it('should return draft submissions', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one.xml')
            .expect(200)
            .then(({ header, text }) => {
              header['content-type'].should.equal('application/xml; charset=utf-8');
              text.should.equal(testData.instances.simple.one);
            })))));

    it('should not return draft submissions nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
            .expect(404)))));

    it('should not carry draft submissions forward to the published version upon publish', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one.xml')
            .expect(404)))));

    it('should not carry over draft submissions when a draft is replaced', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one.xml')
            .expect(404)))));

    it('should not resurface draft submissions when a draft is recreated', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one.xml')
            .expect(404)))));
  });

  describe('/:instanceId GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions/one')
          .expect(404)
          .then(({ body }) => {
            should.not.exist(body.details);
          }))));

    it('should return notfound if the submission does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions/nonexistent').expect(404))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => service.login('chelsea', (asChelsea) =>
            asChelsea.get('/v1/projects/1/forms/simple/submissions/one').expect(403))))));

    it('should return submission details', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
            .expect(200)
            .then(({ body }) => {
              body.should.be.a.Submission();
              body.createdAt.should.be.a.recentIsoDate();
            })))));

    it('should return with extended metadata if requested', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
            .set('X-Extended-Metadata', 'true')
            .expect(200)
            .then(({ body }) => {
              body.should.be.an.ExtendedSubmission();
              body.submitter.displayName.should.equal('Alice');
            })))));
  });

  describe('[draft] /:instanceId GET', () => {
    it('should return submission details', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one')
              .expect(200)
              .then(({ body }) => {
                body.should.be.a.Submission();
                body.createdAt.should.be.a.recentIsoDate();
              }))))));

    it('should not return draft submissions nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
              .expect(404))))));

    it('should not carry draft submissions forward to the published version upon publish', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one')
            .expect(404)))));

    it('should not carry over draft submissions when a draft is replaced', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one')
            .expect(404)))));

    it('should not resurface draft submissions when a draft is recreated', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/draft')
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/submissions')
            .send(testData.instances.simple.one)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft/publish?version=two')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/simple/draft')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/simple/draft/submissions/one')
            .expect(404)))));
  });

  // NOTE: the happy path here is already well-tested above (search mark1).
  // so we only test unhappy paths.
  describe('/:instanceId/attachments GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions/one/attachments').expect(404))));

    it('should return notfound if the submission does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions/nonexistent/attachments').expect(404))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => service.login('chelsea', (asChelsea) =>
            asChelsea.get('/v1/projects/1/forms/simple/submissions/one/attachments').expect(403))))));

    it('should happily return given no attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one/attachments')
            .expect(200)
            .then(({ body }) => {
              body.should.eql([]);
            })))));
  });

  describe('[draft] /:instanceId/attachments GET', () => {
    it('should return draft attachments', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments')
              .expect(200)
              .then(({ body }) => {
                body.should.eql([
                  { name: 'here_is_file2.jpg', exists: false },
                  { name: 'my_file1.mp4', exists: false }
                ]);
              }))))));

    it('should not return draft attachments nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
              .expect(404))))));
  });

  // NOTE: the happy path here is already well-tested above (search mark2).
  // so we only test unhappy paths.
  describe('/:instanceId/attachments/:name GET', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/nonexistent/submissions/one/attachments/file.txt').expect(404))));

    it('should return notfound if the submission does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.get('/v1/projects/1/forms/simple/submissions/nonexistent/attachments/file.txt').expect(404))));

    it('should return notfound if the attachment does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions')
          .send(testData.instances.simple.one)
          .set('Content-Type', 'text/xml')
          .expect(200)
          .then(() => asAlice.get('/v1/projects/1/forms/simple/submissions/one/attachments/file.txt').expect(404)))));

    it('should reject if the user cannot read', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/submission')
          .set('X-OpenRosa-Version', '1.0')
          .attach('xml_submission_file', Buffer.from(testData.instances.simple.one), { filename: 'data.xml' })
          .attach('file.txt', Buffer.from('this is test file one'), { filename: 'file.txt' })
          .expect(201)
          .then(() => service.login('chelsea', (asChelsea) =>
            asChelsea.get('/v1/projects/1/forms/simple/submissions/one/attachments/file.txt').expect(403))))));
  });

  describe('[draft] /:instanceId/attachments/:name GET', () => {
    it('should return a draft attachment', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .send('this is file 1')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .expect(200)
            .then(({ text }) => { text.should.equal('this is file 1'); })))));

    it('should not return a draft attachment nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .send('this is file 1')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
            .expect(404)))));
  });

  describe('/:instanceId/attachments/:name POST', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/nonexistent/submissions/one/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(404))));

    it('should return notfound if the submission does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms/simple/submissions/nonexistent/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(404))));

    it('should reject if the user cannot update a submission', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.post('/v1/projects/1/forms/simple/submissions/one/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(403))));

    it('should reject if the attachment does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/cool_file3.mp3')
              .set('Content-Type', 'audio/mp3')
              .send('testaudio')
              .expect(404))))));

    it('should attach the given file', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
              .set('Content-Type', 'video/mp4')
              .send('testvideo')
              .expect(200)
              .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
                .expect(200)
                .then(({ headers, body }) => {
                  headers['content-type'].should.equal('video/mp4');
                  body.toString().should.equal('testvideo');
                })))))));

    it('should log an audit entry about initial attachment', testService((service, { Audit, Project, Submission, SubmissionAttachment, SubmissionDef }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
            .set('Content-Type', 'video/mp4')
            .send('testvideo')
            .expect(200))
          .then(() => Project.getById(1))
          .then((project) => project.get().getFormByXmlFormId('binaryType'))
          .then((o) => o.get())
          .then((form) => Submission.getById(form.id, 'both', false)
            .then((o) => o.get())
            .then((submission) => submission.getCurrentVersion()
              .then((o) => o.get())
              .then((def) => SubmissionAttachment.getBySubmissionDefIdAndName(def.id, 'my_file1.mp4')
                .then((o) => o.get())
                .then((attachment) => Promise.all([
                  asAlice.get('/v1/users/current').expect(200),
                  Audit.getLatestWhere({ action: 'submission.attachment.update' })
                ])
                  .then(([ user, maybeLog ]) => {
                    maybeLog.isDefined().should.equal(true);
                    const log = maybeLog.get();

                    log.actorId.should.equal(user.body.id);
                    log.acteeId.should.equal(form.acteeId);
                    log.details.should.eql({
                      instanceId: 'both',
                      submissionDefId: def.id,
                      name: 'my_file1.mp4',
                      oldBlobId: null,
                      newBlobId: attachment.blobId
                    });
                  }))))))));

    it('should log an audit entry about reattachment', testService((service, { Audit, Project, Submission, SubmissionAttachment, SubmissionDef }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
            .set('Content-Type', 'video/mp4')
            .send('testvideo')
            .expect(200))
          .then(() => Project.getById(1))
          .then((project) => project.get().getFormByXmlFormId('binaryType'))
          .then((o) => o.get())
          .then((form) => Submission.getById(form.id, 'both', false).then((o) => o.get())
            .then((submission) => submission.getCurrentVersion().then((o) => o.get())
              .then((def) => SubmissionAttachment.getBySubmissionDefIdAndName(def.id, 'my_file1.mp4').then((o) => o.get())
                .then((oldAttachment) => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
                  .set('Content-Type', 'video/mp4')
                  .send('testvideo2')
                  .expect(200)
                  .then((attachment) => Promise.all([
                    asAlice.get('/v1/users/current').expect(200),
                    SubmissionAttachment.getBySubmissionDefIdAndName(def.id, 'my_file1.mp4').then((o) => o.get()),
                    Audit.getLatestWhere({ action: 'submission.attachment.update' })
                  ])
                    .then(([ user, newAttachment, maybeLog ]) => {
                      maybeLog.isDefined().should.equal(true);
                      const log = maybeLog.get();

                      log.actorId.should.equal(user.body.id);
                      log.acteeId.should.equal(form.acteeId);
                      log.details.should.eql({
                        instanceId: 'both',
                        submissionDefId: def.id,
                        name: 'my_file1.mp4',
                        oldBlobId: oldAttachment.blobId,
                        newBlobId: newAttachment.blobId
                      });
                    })))))))));
  });

  // the draft version of this is already tested above with :name GET

  describe('/:instanceId/attachments/:name DELETE', () => {
    it('should return notfound if the form does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.delete('/v1/projects/1/forms/nonexistent/submissions/one/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(404))));

    it('should return notfound if the submission does not exist', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.delete('/v1/projects/1/forms/simple/submissions/nonexistent/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(404))));

    it('should reject if the user cannot update a submission', testService((service) =>
      service.login('chelsea', (asChelsea) =>
        asChelsea.delete('/v1/projects/1/forms/simple/submissions/one/attachments/file.jpg')
          .set('Content-Type', 'image/jpeg')
          .send('testimage')
          .expect(403))));

    it('should clear the given attachment', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200)
            .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
              .set('Content-Type', 'video/mp4')
              .send('testvideo')
              .expect(200)
              .then(() => asAlice.delete('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
                .expect(200)
                .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
                  .expect(404)
                  .then(() => asAlice.get('/v1/projects/1/forms/binaryType/submissions/both/attachments')
                    .expect(200)
                    .then(({ body }) =>  {
                      body.should.eql([
                        { name: 'here_is_file2.jpg', exists: false },
                        { name: 'my_file1.mp4', exists: false }
                      ]);
                    })))))))));

    it('should log an audit entry about the deletion', testService((service, { Audit, Project, Submission, SubmissionAttachment, SubmissionDef }) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms?publish=true')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
            .set('Content-Type', 'video/mp4')
            .send('testvideo')
            .expect(200))
          .then(() => Project.getById(1))
          .then((project) => project.get().getFormByXmlFormId('binaryType'))
          .then((o) => o.get())
          .then((form) => Submission.getById(form.id, 'both', false)
            .then((o) => o.get())
            .then((submission) => submission.getCurrentVersion()
              .then((o) => o.get())
              .then((def) => SubmissionAttachment.getBySubmissionDefIdAndName(def.id, 'my_file1.mp4')
                .then((o) => o.get())
                .then((attachment) => asAlice.delete('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
                  .expect(200)
                  .then(() => Promise.all([
                    asAlice.get('/v1/users/current').expect(200),
                    Audit.getLatestWhere({ action: 'submission.attachment.update' })
                  ])
                    .then(([ user, maybeLog ]) => {
                      maybeLog.isDefined().should.equal(true);
                      const log = maybeLog.get();

                      log.actorId.should.equal(user.body.id);
                      log.acteeId.should.equal(form.acteeId);
                      log.details.should.eql({
                        instanceId: 'both',
                        submissionDefId: def.id,
                        name: 'my_file1.mp4',
                        oldBlobId: attachment.blobId
                      });
                    })))))))));
  });

  describe('[draft] /:instanceId/attachments/:name DELETE', () => {
    it('should delete a draft attachment', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .send('this is file 1')
            .expect(200))
          .then(() => asAlice.delete('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .expect(200))
          .then(() => asAlice.get('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .expect(404)))));

    it('should not delete a draft attachment nondraft', testService((service) =>
      service.login('alice', (asAlice) =>
        asAlice.post('/v1/projects/1/forms')
          .set('Content-Type', 'application/xml')
          .send(testData.forms.binaryType)
          .expect(200)
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions')
            .send(testData.instances.binaryType.both)
            .set('Content-Type', 'text/xml')
            .expect(200))
          .then(() => asAlice.post('/v1/projects/1/forms/binaryType/draft/submissions/both/attachments/my_file1.mp4')
            .send('this is file 1')
            .expect(200))
          .then(() => asAlice.delete('/v1/projects/1/forms/binaryType/submissions/both/attachments/my_file1.mp4')
            .expect(404)))));
  });
});

