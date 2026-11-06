const express = require('express');
const { fn, col, literal } = require('sequelize');
const { Log, Alert, Incident, Asset, AuditLog, User } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');
const aiService = require('../services/aiService');
const threatIntel = require('../services/threatIntel');

const router = express.Router();

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

async function buildReport() {
  const [totalEvents, totalAlerts, criticalAlerts, highAlerts, openIncidents, totalAssets] = await Promise.all([
    Log.count(),
    Alert.count(),
    Alert.count({ where: { severity: 'CRITICAL' } }),
    Alert.count({ where: { severity: 'HIGH' } }),
    Incident.count({ where: { status: ['OPEN', 'INVESTIGATING'] } }),
    Asset.count(),
  ]);

  const topIps = await Alert.findAll({
    attributes: ['source_ip', [fn('COUNT', col('source_ip')), 'count']],
    where: literal('source_ip IS NOT NULL'),
    group: ['source_ip'],
    order: [[literal('count'), 'DESC']],
    limit: 10,
    raw: true,
  });

  const topRules = await Alert.findAll({
    attributes: ['rule_name', [fn('COUNT', col('rule_name')), 'count']],
    group: ['rule_name'],
    order: [[literal('count'), 'DESC']],
    limit: 10,
    raw: true,
  });

  return {
    generated_at: new Date().toISOString(),
    summary: { totalEvents, totalAlerts, criticalAlerts, highAlerts, openIncidents, totalAssets },
    topAttackingIps: topIps,
    topDetectionRules: topRules,
  };
}

router.get('/reports', requireAuth, async (req, res) => {
  try {
    const report = await buildReport();
    res.render('reports', { title: 'Reports', report });
  } catch (err) {
    console.error('Reports page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not build report.', user: req.session.user });
  }
});

router.get('/reports/export.json', requireAuth, async (req, res) => {
  try {
    const report = await buildReport();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="soc-report.json"');
    res.send(JSON.stringify(report, null, 2));
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
});

function toCsvValue(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return `"${s.replace(/"/g, '""')}"`;
}

router.get('/reports/export.csv', requireAuth, async (req, res) => {
  try {
    const report = await buildReport();
    const lines = [];
    lines.push('Section,Key,Value');
    Object.entries(report.summary).forEach(([k, v]) => {
      lines.push(['Summary', k, v].map(toCsvValue).join(','));
    });
    report.topAttackingIps.forEach((r) => {
      lines.push(['Top Attacking IPs', r.source_ip, r.count].map(toCsvValue).join(','));
    });
    report.topDetectionRules.forEach((r) => {
      lines.push(['Top Detection Rules', r.rule_name, r.count].map(toCsvValue).join(','));
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="soc-report.csv"');
    res.send(lines.join('\n'));
  } catch (err) {
    res.status(500).json({ error: 'Export failed' });
  }
});

// ---- Settings ----

router.get('/settings', requireAuth, async (req, res) => {
  try {
    const auditLogs = await AuditLog.findAll({
      include: [{ model: User, as: 'user', attributes: ['username'], required: false }],
      order: [['created_at', 'DESC']],
      limit: 50,
    });

    res.render('settings', {
      title: 'Settings',
      aiEnabled: aiService.isEnabled(),
      aiProvider: aiService.providerLabel(),
      tiProviders: threatIntel.configuredProviders(),
      auditLogs,
    });
  } catch (err) {
    console.error('Settings page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load settings.', user: req.session.user });
  }
});

module.exports = router;
