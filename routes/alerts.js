const express = require('express');
const { Op } = require('sequelize');
const { Alert, Log, AuditLog, ThreatIntel } = require('../models');
const { requireAuth } = require('../middleware/auth');
const mitre = require('../services/mitre');

const router = express.Router();

const VALID_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];

router.get('/alerts', requireAuth, async (req, res) => {
  try {
    const { severity, status, search, sourceIp, dateFrom, dateTo } = req.query;
    const where = {};

    if (severity) where.severity = severity;
    if (status) where.status = status;
    if (sourceIp) where.source_ip = { [Op.like]: `%${sourceIp}%` };

    if (dateFrom || dateTo) {
      where.created_at = {};
      if (dateFrom) where.created_at[Op.gte] = new Date(dateFrom);
      if (dateTo) where.created_at[Op.lte] = new Date(dateTo);
    }

    if (search) {
      where[Op.or] = [
        { title: { [Op.like]: `%${search}%` } },
        { source_ip: { [Op.like]: `%${search}%` } },
        { hostname: { [Op.like]: `%${search}%` } },
        { username: { [Op.like]: `%${search}%` } },
      ];
    }

    const alerts = await Alert.findAll({
      where,
      order: [['created_at', 'DESC']],
      limit: 200,
    });

    res.render('alerts', {
      title: 'Alerts',
      alerts,
      filters: {
        severity: severity || '',
        status: status || '',
        search: search || '',
        sourceIp: sourceIp || '',
        dateFrom: dateFrom || '',
        dateTo: dateTo || '',
      },
    });
  } catch (err) {
    console.error('Alerts page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load alerts.', user: req.session.user });
  }
});

router.get('/alerts/:id', requireAuth, async (req, res) => {
  try {
    const alert = await Alert.findByPk(req.params.id);
    if (!alert) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Alert not found.', user: req.session.user });
    }

    let relatedLogs = [];
    if (alert.related_log_ids) {
      try {
        const ids = JSON.parse(alert.related_log_ids);
        relatedLogs = await Log.findAll({ where: { id: { [Op.in]: ids } }, order: [['timestamp', 'ASC']] });
      } catch (e) {
        relatedLogs = [];
      }
    }

    const technique = alert.mitre_id ? mitre.getTechnique(alert.mitre_id) : null;

    let intel = null;
    if (alert.source_ip) {
      intel = await ThreatIntel.findOne({
        where: { indicator: alert.source_ip },
        order: [['checked_at', 'DESC']],
      });
    }

    res.render('alert-details', {
      title: `Alert #${alert.id}`,
      alert,
      relatedLogs,
      technique,
      intel,
    });
  } catch (err) {
    console.error('Alert detail error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load alert.', user: req.session.user });
  }
});

router.post('/alerts/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body;

  if (!VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const alert = await Alert.findByPk(req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const previousStatus = alert.status;
    alert.status = status;
    await alert.save();

    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'ALERT_STATUS_CHANGED',
      target: `Alert #${alert.id} -> ${status}`,
      ip: req.ip,
    }).catch(() => {});

    const io = req.app.get('io');
    if (io) io.emit('alert_updated', { id: alert.id, status: alert.status, previousStatus });

    res.json({ success: true, status: alert.status });
  } catch (err) {
    console.error('Alert status update error:', err);
    res.status(500).json({ error: 'Failed to update alert' });
  }
});

module.exports = router;
