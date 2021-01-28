// Copyright 2017 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const Problem = require('../util/problem');
const { isBlank, isDevelopmentEnv } = require('../util/util');
const { getOrReject } = require('../util/promise');
const { success } = require('../util/http');

const useSecureCookies = !isDevelopmentEnv()
const COOKIE_NAME = useSecureCookies ? '__Host-session' : 'session';

module.exports = (service, endpoint) => {

  service.post('/sessions', endpoint(({ User, Session, crypto }, { body }) => {
    const { email, password } = body;

    if (isBlank(email) || isBlank(password))
      return Problem.user.missingParameters({ expected: [ 'email', 'password' ], got: { email, password } });

    return User.getByEmail(email)
      .then(getOrReject(Problem.user.authenticationFailed()))
      .then((user) => crypto.verifyPassword(password, user.password)
        .then((verified) => ((verified !== true)
          ? Problem.user.authenticationFailed()
          : Session.fromActor(user.actor).create()
            .then((session) => (_, response) => {
              response.cookie(COOKIE_NAME, session.token, { path: '/', expires: session.expiresAt,
                httpOnly: true, secure: useSecureCookies, sameSite: 'strict' });
              response.cookie('__csrf', session.csrf, { expires: session.expiresAt,
                secure: useSecureCookies, sameSite: 'strict' });

              return session;
            }))));
  }));

  service.get('/sessions/restore', endpoint((_, { auth }) =>
    auth.session().orElse(Problem.user.notFound())));

  // here we always throw a 403 even if the token doesn't exist to prevent
  // information leakage.
  // TODO: but a timing attack still exists here. :(
  service.delete('/sessions/:token', endpoint(({ Audit, Session }, { auth, params }) =>
    Session.getByBearerToken(params.token)
      .then(getOrReject(Problem.user.insufficientRights()))
      .then((token) => auth.canOrReject('session.end', token.actor)
        .then(() => Promise.all([
          token.delete(),
          ((token.actor.type !== 'field_key' && token.actor.type !== 'public_link')
            ? Promise.resolve()
            : Audit.log(auth.actor(), 'session.end', token.actor))
        ]))
        .then(() => (_, response) => {
          // revoke the cookie associated w the session, if the session was used to
          // terminate itself.
          // TODO: repetitive w above.
          if (token.token === auth.session().map((s) => s.token).orNull())
            response.cookie(COOKIE_NAME, 'null', { path: '/', expires: new Date(0),
              httpOnly: true, secure: true, sameSite: 'strict' });

          return success;
        }))));

};
