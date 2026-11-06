const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Op } = require('sequelize');
const { User, AuditLog } = require('../models');
const { requireRole } = require('../middleware/auth');

const router = express.Router();
const ROLES = ['ADMIN', 'ANALYST', 'VIEWER'];
const DISABLED_UNTIL = new Date('2100-01-01T00:00:00Z');

const isDisabled = (u) => u.lockedUntil && new Date(u.lockedUntil) > new Date('2090-01-01');

function audit(req, action, target) {
  return AuditLog.create({ user_id: req.session.user.id, action, target, ip: req.ip }).catch(() => {});
}

async function renderUsers(req, res, extra = {}) {
  const users = await User.findAll({ order: [['id', 'ASC']] });
  res.render('users', {
    title: 'User Management',
    users: users.map((u) => ({ ...u.toJSON(), disabled: isDisabled(u) })),
    roles: ROLES,
    notice: null,
    error: null,
    ...extra,
  });
}

/** Counts admins other than `exceptId` who can still log in. */
async function otherActiveAdmins(exceptId) {
  const admins = await User.findAll({ where: { role: 'ADMIN', id: { [Op.ne]: exceptId } } });
  return admins.filter((a) => !isDisabled(a)).length;
}

router.get('/users', requireRole('ADMIN'), async (req, res) => {
  try { await renderUsers(req, res); } catch (err) {
    console.error('Users page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load users.' });
  }
});

router.post('/users', requireRole('ADMIN'), async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const role = req.body.role;

    if (!name || name.length > 60) return renderUsers(req, res, { error: 'Name is required (max 60 characters).' });
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return renderUsers(req, res, { error: 'Username: 3-32 letters, numbers, dot, dash or underscore.' });
    if (password.length < 10) return renderUsers(req, res, { error: 'Password must be at least 10 characters.' });
    if (!ROLES.includes(role)) return renderUsers(req, res, { error: 'Invalid role.' });
    if (await User.findOne({ where: { username } })) return renderUsers(req, res, { error: 'That username already exists.' });

    await User.create({
      name, username, role,
      password: await bcrypt.hash(password, 12),
      mustChangePassword: true,
    });
    await audit(req, 'USER_CREATED', `${username} (${role})`);
    return renderUsers(req, res, { notice: `User "${username}" created. They must change the password on first login.` });
  } catch (err) {
    console.error('Create user error:', err);
    return res.status(500).render('error', { title: 'Server Error', message: 'Could not create user.' });
  }
});

router.post('/users/:id/role', requireRole('ADMIN'), async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).render('error', { title: 'Not Found', message: 'User not found.' });
    if (!ROLES.includes(req.body.role)) return renderUsers(req, res, { error: 'Invalid role.' });

    if (user.role === 'ADMIN' && req.body.role !== 'ADMIN' && (await otherActiveAdmins(user.id)) === 0) {
      return renderUsers(req, res, { error: 'You cannot demote the last active admin.' });
    }
    user.role = req.body.role;
    await user.save();
    await audit(req, 'USER_ROLE_CHANGED', `${user.username} -> ${user.role}`);
    return renderUsers(req, res, { notice: `Role for "${user.username}" is now ${user.role}.` });
  } catch (err) {
    console.error('Role change error:', err);
    return res.status(500).render('error', { title: 'Server Error', message: 'Could not change role.' });
  }
});

router.post('/users/:id/reset-password', requireRole('ADMIN'), async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).render('error', { title: 'Not Found', message: 'User not found.' });

    const temp = crypto.randomBytes(9).toString('base64url');
    user.password = await bcrypt.hash(temp, 12);
    user.mustChangePassword = true;
    user.failedLoginAttempts = 0;
    if (!isDisabled(user)) user.lockedUntil = null;
    await user.save();
    await audit(req, 'USER_PASSWORD_RESET', user.username);
    return renderUsers(req, res, { notice: `Temporary password for "${user.username}": ${temp}  (shown once - they must change it at next login)` });
  } catch (err) {
    console.error('Reset password error:', err);
    return res.status(500).render('error', { title: 'Server Error', message: 'Could not reset password.' });
  }
});

router.post('/users/:id/toggle', requireRole('ADMIN'), async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).render('error', { title: 'Not Found', message: 'User not found.' });

    if (user.id === req.session.user.id) return renderUsers(req, res, { error: 'You cannot disable your own account.' });

    if (isDisabled(user)) {
      user.lockedUntil = null;
      user.failedLoginAttempts = 0;
    } else {
      if (user.role === 'ADMIN' && (await otherActiveAdmins(user.id)) === 0) {
        return renderUsers(req, res, { error: 'You cannot disable the last active admin.' });
      }
      user.lockedUntil = DISABLED_UNTIL;
    }
    await user.save();
    await audit(req, isDisabled(user) ? 'USER_DISABLED' : 'USER_ENABLED', user.username);
    return renderUsers(req, res, { notice: `User "${user.username}" ${isDisabled(user) ? 'disabled' : 'enabled'}.` });
  } catch (err) {
    console.error('Toggle user error:', err);
    return res.status(500).render('error', { title: 'Server Error', message: 'Could not update user.' });
  }
});

module.exports = router;
