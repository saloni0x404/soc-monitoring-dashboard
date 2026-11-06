const express = require('express');
const { Op } = require('sequelize');
const { Incident, Alert, User, AuditLog } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

const VALID_STATUSES = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED'];

router.get('/incidents', requireAuth, async (req, res) => {
  try {
    const { status, severity } = req.query;
    const where = {};
    if (status) where.status = status;
    if (severity) where.severity = severity;

    const incidents = await Incident.findAll({ where, order: [['created_at', 'DESC']], limit: 200 });
    res.render('incidents', {
      title: 'Incidents',
      incidents,
      filters: { status: status || '', severity: severity || '' },
    });
  } catch (err) {
    console.error('Incidents page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load incidents.', user: req.session.user });
  }
});

// Create an incident from an existing alert
router.post('/incidents/from-alert/:alertId', requireAuth, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const alert = await Alert.findByPk(req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    const incident = await Incident.create({
      title: `Incident: ${alert.title}`,
      description: `Escalated from Alert #${alert.id}.\n\n${alert.description || ''}`,
      severity: alert.severity,
      status: 'OPEN',
      assigned_to: req.session.user.username,
      related_alert_ids: JSON.stringify([alert.id]),
    });

    alert.status = 'INVESTIGATING';
    await alert.save();

    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'INCIDENT_CREATED',
      target: `Incident #${incident.id} from Alert #${alert.id}`,
      ip: req.ip,
    }).catch(() => {});

    const io = req.app.get('io');
    if (io) io.emit('new_incident', incident.toJSON());

    res.json({ success: true, incidentId: incident.id });
  } catch (err) {
    console.error('Create incident error:', err);
    res.status(500).json({ error: 'Failed to create incident' });
  }
});

router.get('/incidents/:id', requireAuth, async (req, res) => {
  try {
    const incident = await Incident.findByPk(req.params.id);
    if (!incident) {
      return res.status(404).render('error', { title: 'Not Found', message: 'Incident not found.', user: req.session.user });
    }

    let relatedAlerts = [];
    if (incident.related_alert_ids) {
      try {
        const ids = JSON.parse(incident.related_alert_ids);
        relatedAlerts = await Alert.findAll({ where: { id: { [Op.in]: ids } } });
      } catch (e) { relatedAlerts = []; }
    }

    const analysts = await User.findAll({ attributes: ['username'], order: [['username', 'ASC']] });

    res.render('incident-details', {
      title: `Incident #${incident.id}`,
      incident,
      relatedAlerts,
      analysts,
      statuses: VALID_STATUSES,
    });
  } catch (err) {
    console.error('Incident detail error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load incident.', user: req.session.user });
  }
});

router.post('/incidents/:id/update', requireAuth, requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  try {
    const incident = await Incident.findByPk(req.params.id);
    if (!incident) return res.status(404).render('error', { title: 'Not Found', message: 'Incident not found.', user: req.session.user });

    const { status, assigned_to, notes, resolution } = req.body;

    if (status && VALID_STATUSES.includes(status)) incident.status = status;
    if (typeof assigned_to === 'string') incident.assigned_to = assigned_to;
    if (typeof notes === 'string') incident.notes = notes;
    if (typeof resolution === 'string') incident.resolution = resolution;

    await incident.save();

    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'INCIDENT_UPDATED',
      target: `Incident #${incident.id}`,
      ip: req.ip,
    }).catch(() => {});

    const io = req.app.get('io');
    if (io) io.emit('incident_updated', incident.toJSON());

    res.redirect(`/incidents/${incident.id}`);
  } catch (err) {
    console.error('Incident update error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not update incident.', user: req.session.user });
  }
});

module.exports = router;
