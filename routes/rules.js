const express = require('express');
const { Op } = require('sequelize');
const { Rule, AuditLog } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

router.get('/rules', requireAuth, async (req, res) => {
  try {
    const { search = '', severity = '', status = '' } = req.query;
    const where = {};
    if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(severity)) where.severity = severity;
    if (status === 'enabled') where.enabled = true;
    if (status === 'disabled') where.enabled = false;
    if (search.trim()) where[Op.or] = [
      { title: { [Op.like]: `%${search.trim()}%` } },
      { name: { [Op.like]: `%${search.trim()}%` } },
      { description: { [Op.like]: `%${search.trim()}%` } },
      { mitre_id: { [Op.like]: `%${search.trim()}%` } },
    ];
    const rules = await Rule.findAll({ where, order: [['id', 'ASC']] });
    res.render('rules', { title: 'Detection Rules', rules, filters: { search, severity, status }, updated: req.query.updated || '' });
  } catch (err) {
    console.error('Rules page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load rules.', user: req.session.user });
  }
});

router.post('/rules/:id/toggle', requireRole('ADMIN'), async (req, res) => {
  try {
    const rule = await Rule.findByPk(req.params.id);
    if (!rule) return res.status(404).redirect('/rules?updated=not-found');
    rule.enabled = !rule.enabled;
    await rule.save();
    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'DETECTION_RULE_TOGGLED',
      target: `${rule.name} -> ${rule.enabled ? 'enabled' : 'disabled'}`,
      ip: req.ip,
    }).catch(() => {});
    res.redirect(`/rules?updated=${rule.enabled ? 'enabled' : 'disabled'}`);
  } catch (err) {
    console.error('Rule toggle error:', err);
    res.status(500).redirect('/rules?updated=error');
  }
});

module.exports = router;
