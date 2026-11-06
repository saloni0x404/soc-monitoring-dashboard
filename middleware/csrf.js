/**
 * csrf.js - session-bound CSRF protection (no extra dependency).
 *
 * - A random token lives in the session and is exposed to views as `csrfToken`.
 * - Every POST/PUT/PATCH/DELETE must send it back, either as a hidden form
 *   field `_csrf` or an `X-CSRF-Token` header (public/js/csrf.js adds both
 *   automatically to forms and fetch() calls).
 * - Compared in constant time.
 */
const crypto = require('crypto');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function tokensMatch(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function csrfProtection(req, res, next) {
  if (!req.session) return next(new Error('CSRF middleware needs a session'));
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken = req.session.csrfToken;

  if (SAFE_METHODS.has(req.method)) return next();

  const supplied = req.get('x-csrf-token') || (req.body && req.body._csrf);
  if (tokensMatch(supplied, req.session.csrfToken)) return next();

  const wantsJson = req.xhr || (req.get('accept') || '').includes('application/json')
    || (req.get('content-type') || '').includes('application/json')
    || /^\/(simulator|ingest|api)/.test(req.path);
  if (wantsJson) return res.status(403).json({ error: 'Invalid or missing CSRF token. Refresh the page and try again.' });
  return res.status(403).render('error', {
    title: 'Forbidden',
    message: 'Your form session expired or was invalid. Go back, refresh the page and try again.',
  });
}

module.exports = { csrfProtection, tokensMatch };
