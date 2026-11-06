const express = require('express');
const { Op } = require('sequelize');
const { Alert, Log, Incident, AuditLog } = require('../models');
const { requireAuth } = require('../middleware/auth');
const aiService = require('../services/aiService');
const mitre = require('../services/mitre');

const router = express.Router();

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

// ---- Safe, read-only data functions the chatbot may use ----
// The AI selects a NAME from this list; it never writes or runs SQL.
const SAFE_DATA_FUNCTIONS = {
  async getDashboardStats() {
    return {
      totalEvents: await Log.count(),
      criticalAlerts: await Alert.count({ where: { severity: 'CRITICAL', status: OPEN_STATUSES } }),
      highAlerts: await Alert.count({ where: { severity: 'HIGH', status: OPEN_STATUSES } }),
      openIncidents: await Incident.count({ where: { status: ['OPEN', 'INVESTIGATING'] } }),
    };
  },
  async getCriticalAlerts() {
    const alerts = await Alert.findAll({
      where: { severity: 'CRITICAL' },
      order: [['created_at', 'DESC']],
      limit: 10,
    });
    return alerts.map((a) => ({ id: a.id, title: a.title, source_ip: a.source_ip, risk_score: a.risk_score, status: a.status }));
  },
  async getRecentAlerts() {
    const alerts = await Alert.findAll({ order: [['created_at', 'DESC']], limit: 10 });
    return alerts.map((a) => ({ id: a.id, title: a.title, severity: a.severity, source_ip: a.source_ip, status: a.status }));
  },
  async getOpenIncidents() {
    const incidents = await Incident.findAll({ where: { status: ['OPEN', 'INVESTIGATING'] }, limit: 10 });
    return incidents.map((i) => ({ id: i.id, title: i.title, severity: i.severity, status: i.status, assigned_to: i.assigned_to }));
  },
  async searchLogs() {
    const logs = await Log.findAll({ order: [['timestamp', 'DESC']], limit: 15 });
    return logs.map((l) => ({ time: l.timestamp, type: l.event_type, severity: l.severity, source_ip: l.source_ip, message: l.message }));
  },
};

router.get('/ai', requireAuth, async (req, res) => {
  try {
    const alerts = await Alert.findAll({ order: [['created_at', 'DESC']], limit: 50 });
    res.render('ai', {
      title: 'AI Security Analyst',
      alerts,
      aiEnabled: aiService.isEnabled(),
      provider: aiService.providerLabel(),
    });
  } catch (err) {
    console.error('AI page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load AI page.', user: req.session.user });
  }
});

router.post('/ai/analyze/:alertId', requireAuth, async (req, res) => {
  if (!aiService.isEnabled()) {
    return res.status(503).json({ error: 'AI is not configured. Set AI_PROVIDER and the matching key in .env.' });
  }
  try {
    const alert = await Alert.findByPk(req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    let relatedLogs = [];
    if (alert.related_log_ids) {
      try {
        const ids = JSON.parse(alert.related_log_ids);
        relatedLogs = await Log.findAll({ where: { id: { [Op.in]: ids } }, limit: 20 });
      } catch (e) { relatedLogs = []; }
    }

    const technique = alert.mitre_id ? mitre.getTechnique(alert.mitre_id) : null;
    const analysis = await aiService.analyzeAlert(alert, relatedLogs, technique);

    await AuditLog.create({
      user_id: req.session.user.id,
      action: 'AI_ANALYSIS_REQUESTED',
      target: `Alert #${alert.id}`,
      ip: req.ip,
    }).catch(() => {});

    res.json({ success: true, analysis });
  } catch (err) {
    console.error('AI analyze error:', err);
    res.status(500).json({ error: `AI request failed: ${err.message}` });
  }
});

router.post('/ai/chat', requireAuth, async (req, res) => {
  if (!aiService.isEnabled()) {
    return res.status(503).json({ error: 'AI is not configured. Set AI_PROVIDER and the matching key in .env.' });
  }
  const question = (req.body.question || '').trim();
  if (!question) return res.status(400).json({ error: 'Question is required' });

  try {
    const fnName = await aiService.chooseFunction(question);

    if (!fnName || !SAFE_DATA_FUNCTIONS[fnName]) {
      return res.json({
        success: true,
        answer: "I can only answer questions about dashboard stats, alerts, incidents, and recent logs. Try asking something like \"show me today's critical alerts\" or \"what are the open incidents?\"",
        functionUsed: null,
      });
    }

    const data = await SAFE_DATA_FUNCTIONS[fnName]();
    const answer = await aiService.answerWithData(question, fnName, data);

    res.json({ success: true, answer, functionUsed: fnName });
  } catch (err) {
    console.error('AI chat error:', err);
    res.status(500).json({ error: `AI request failed: ${err.message}` });
  }
});

module.exports = router;
