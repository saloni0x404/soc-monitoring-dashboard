const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const isProd = process.env.NODE_ENV === 'production';
const CDN = 'https://cdn.jsdelivr.net';

// Strict CSP: only our own origin plus the jsDelivr CDN (Bootstrap, icons,
// Chart.js). No inline <script> is allowed anywhere. Set CSP_REPORT_ONLY=true
// to log violations in the browser console instead of blocking while testing.
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    reportOnly: process.env.CSP_REPORT_ONLY === 'true',
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'", CDN],
      'script-src-attr': ["'none'"],
      'style-src': ["'self'", CDN, "'unsafe-inline'"],
      'font-src': ["'self'", CDN, 'data:'],
      'img-src': ["'self'", 'data:'],
      'connect-src': ["'self'", 'ws:', 'wss:'],
      'object-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"],
      'frame-ancestors': ["'none'"],
      'upgrade-insecure-requests': isProd ? [] : null,
    },
  },
});

const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again later.',
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { helmetMiddleware, loginLimiter, apiLimiter };
