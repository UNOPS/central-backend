// Copyright 2017 ODK Central Developers
// See the NOTICE file at the top-level directory of this distribution and at
// https://github.com/opendatakit/central-backend/blob/master/NOTICE.
// This file is part of ODK Central. It is subject to the license terms in
// the LICENSE file found in the top-level directory of this distribution and at
// https://www.apache.org/licenses/LICENSE-2.0. No part of ODK Central,
// including this file, may be copied, modified, propagated, or distributed
// except according to the terms contained in the LICENSE file.

const { DateTime } = require('luxon');
const Problem = require('../util/problem');
const { isBlank, isDevelopmentEnv } = require('../util/util');
const { getOrReject } = require('../util/promise');
const { success, withCookie } = require('../util/http');


const COOKIE_NAME =  isDevelopmentEnv() ? 'session' : '__Host-session';

const withSessionCookie = withCookie(COOKIE_NAME);
const cookieFor = (session) => (
  isDevelopmentEnv()
  ? [
    session.token,
    'Path=/',
    `Expires=${DateTime.fromJSDate(session.expiresAt).toHTTP()}`,
  ]
  : [
    session.token,
    'Path=/',
    `Expires=${DateTime.fromJSDate(session.expiresAt).toHTTP()}`,
    'SameSite=Strict',
    'HttpOnly',
    'Secure'
  ]
).join('; ');

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
            .then((session) => withSessionCookie(cookieFor(session))(session)))));
  }));

  service.get('/sessions/restore', endpoint((_, { auth }) =>
    auth.session().orElse(Problem.user.notFound())));

  // here we always throw a 403 even if the token doesn't exist to prevent
  // information leakage.
  // TODO: but a timing attack still exists here. :(
  service.delete('/sessions/:token', endpoint(({ Session }, { auth, params }) =>
    Session.getByBearerToken(params.token)
      .then(getOrReject(Problem.user.insufficientRights()))
      .then((token) => auth.canOrReject('session.end', token.actor)
        .then(() => token.delete())
        .then(() => withSessionCookie('null; Expires=Thu, 01 Jan 1970 00:00:00 GMT')(success)))));

};

