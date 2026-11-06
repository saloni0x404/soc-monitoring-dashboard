const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const { User, AuditLog } = require('../models');
const { loginLimiter } = require('../middleware/security');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const LOCK_THRESHOLD = 5;
const LOCK_MINUTES = 15;

function logAudit(user_id, action, target, ip) {
  return AuditLog.create({ user_id, action, target, ip }).catch(() => {});
}

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { error: null, title: 'Login', layout: false });
});

router.post(
  '/login',
  loginLimiter,
  [
    body('username').trim().notEmpty(),
    body('password').notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('login', { error: 'Username and password are required.', title: 'Login', layout: false });
    }

    const { username, password } = req.body;
    const ip = req.ip;

    try {
      const user = await User.findOne({ where: { username } });

      if (!user) {
        await logAudit(null, 'LOGIN_FAILED', username, ip);
        return res.status(401).render('login', { error: 'Invalid username or password.', title: 'Login', layout: false });
      }

      if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
        const minutesLeft = Math.ceil((new Date(user.lockedUntil) - new Date()) / 60000);
        return res.status(423).render('login', {
          error: `Account locked. Try again in ${minutesLeft} minute(s).`,
          title: 'Login',
          layout: false,
        });
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        user.failedLoginAttempts += 1;
        if (user.failedLoginAttempts >= LOCK_THRESHOLD) {
          user.lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60 * 1000);
          user.failedLoginAttempts = 0;
        }
        await user.save();
        await logAudit(user.id, 'LOGIN_FAILED', username, ip);
        return res.status(401).render('login', { error: 'Invalid username or password.', title: 'Login', layout: false });
      }

      user.failedLoginAttempts = 0;
      user.lockedUntil = null;
      user.lastLogin = new Date();
      await user.save();

      req.session.regenerate((err) => {
        if (err) {
          return res.status(500).render('login', { error: 'Login failed. Please try again.', title: 'Login', layout: false });
        }
        req.session.user = {
          id: user.id,
          name: user.name,
          username: user.username,
          role: user.role,
          mustChangePassword: user.mustChangePassword,
        };
        logAudit(user.id, 'LOGIN_SUCCESS', username, ip);

        if (user.mustChangePassword) {
          return res.redirect('/change-password');
        }
        return res.redirect('/');
      });
    } catch (err) {
      console.error('Login error:', err);
      return res.status(500).render('login', { error: 'Something went wrong. Please try again.', title: 'Login', layout: false });
    }
  }
);

router.get('/change-password', requireAuth, (req, res) => {
  res.render('change-password', { error: null, title: 'Change Password', layout: false });
});

router.post(
  '/change-password',
  requireAuth,
  [
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters.'),
    body('confirmPassword').custom((value, { req }) => value === req.body.newPassword),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render('change-password', {
        error: 'Passwords must match and be at least 8 characters.',
        title: 'Change Password',
        layout: false,
      });
    }

    try {
      const user = await User.findByPk(req.session.user.id);
      const hash = await bcrypt.hash(req.body.newPassword, 12);
      user.password = hash;
      user.mustChangePassword = false;
      await user.save();

      req.session.user.mustChangePassword = false;
      await logAudit(user.id, 'PASSWORD_CHANGED', user.username, req.ip);

      return res.redirect('/');
    } catch (err) {
      console.error('Change password error:', err);
      return res.status(500).render('change-password', { error: 'Something went wrong.', title: 'Change Password', layout: false });
    }
  }
);

router.post('/logout', requireAuth, (req, res) => {
  const user = req.session.user;
  req.session.destroy(() => {
    if (user) logAudit(user.id, 'LOGOUT', user.username, req.ip);
    res.redirect('/login');
  });
});

module.exports = router;
