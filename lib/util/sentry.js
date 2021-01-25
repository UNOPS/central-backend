const { inspect } = require('util');
const { isBlank } = require('./util');

const sensitiveEndpoints = ['/users/reset/verify', '/users/(.*?)/password'];

const init = (config) => {
  if ((config == null) || isBlank(config.key) || isBlank(config.project)) {
    // return a noop object that returns the hooks but does nothing.
    return {
      Handlers: {
        requestHandler() { return (request, response, next) => next(); },
        errorHandler() { return (error, request, response, next) => next(error); }
      },
      captureException(err) {
        process.stderr.write('attempted to log Sentry exception in development:\n');
        process.stderr.write(inspect(err));
        process.stderr.write('\n');
      }
    };
  }

  // otherwise initialize Sentry with some settings we want.
  const Sentry = require('@sentry/node');
  Sentry.init({
    dsn: `https://${config.key}@sentry.io/${config.project}`,
    beforeSend(event) {
      if (event.request) {
        // clear out all cookie values
        if (event.request.headers && event.request.headers.cookie) {
          const cookies = event.request.headers.cookie.split('; ')
            .map((cookie) => cookie.slice(0, cookie.indexOf('=')))
            .join(', ');

          event.request.headers.cookie = cookies; // eslint-disable-line no-param-reassign
        }

        // clear out all request body data for sensitive endpoints (logging in, etc)
        if (event.request.url) {
          for (const endpoint of sensitiveEndpoints) {
            if (event.request.url.match(endpoint)) {
              event.request.data = null; // eslint-disable-line no-param-reassign
            }
          }
        }
      }

      // only file the event if it is a bare exception or it is a true 500.x Problem.
      const error = event.extra.Error;
      if (error == null) return event; // we aren't sure why there isn't an exception; pass through.
      if ((error.isProblem !== true) || (error.httpCode === 500)) return event; // throw exceptions.
      return null; // we have a user-space problem.
    }
  });
  return Sentry;
};

module.exports = { init };

