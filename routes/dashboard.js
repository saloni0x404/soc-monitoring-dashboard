const express = require('express');
const { fn, col, literal } = require('sequelize');
const { requireAuth } = require('../middleware/auth');
const { Log, Alert, Incident, Asset, ThreatIntel, Rule } = require('../models');

const router = express.Router();

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

router.get('/', requireAuth, async (req, res) => {
  if (req.session.user.mustChangePassword) {
    return res.redirect('/change-password');
  }

  try {
    const [totalEvents, totalAlerts, criticalAlerts, highAlerts, mediumAlerts, lowAlerts, openIncidents, activeAssets, maliciousIps, enabledRules] = await Promise.all([
      Log.count(),
      Alert.count(),
      Alert.count({ where: { severity: 'CRITICAL', status: OPEN_STATUSES } }),
      Alert.count({ where: { severity: 'HIGH', status: OPEN_STATUSES } }),
      Alert.count({ where: { severity: 'MEDIUM', status: OPEN_STATUSES } }),
      Alert.count({ where: { severity: 'LOW', status: OPEN_STATUSES } }),
      Incident.count({ where: { status: ['OPEN', 'INVESTIGATING'] } }),
      Asset.count({ where: { status: 'ACTIVE' } }),
      ThreatIntel.count({ where: { reputation: 'MALICIOUS' }, distinct: true, col: 'indicator' }),
      Rule.count({ where: { enabled: true } }),
    ]);

    // ---- Chart data ----
    // Events over the last 24 hours, bucketed by hour
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentLogs = await Log.findAll({
      attributes: ['timestamp', 'source', 'severity'],
      where: { timestamp: { [require('sequelize').Op.gte]: since } },
      raw: true,
    });

    const hourBuckets = Array(24).fill(0);
    const nowHour = new Date().getUTCHours();
    recentLogs.forEach((l) => {
      const hoursAgo = Math.floor((Date.now() - new Date(l.timestamp).getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) hourBuckets[23 - hoursAgo] += 1;
    });
    const hourLabels = Array.from({ length: 24 }, (_, i) => `${(nowHour - 23 + i + 24) % 24}:00`);

    const [latestAlerts, latestLogs, latestIncidents] = await Promise.all([
      Alert.findAll({ order: [['created_at', 'DESC']], limit: 6, raw: true }),
      Log.findAll({ order: [['timestamp', 'DESC']], limit: 6, raw: true }),
      Incident.findAll({ order: [['updated_at', 'DESC']], limit: 5, raw: true }),
    ]);

    const severityCounts = await Alert.findAll({
      attributes: ['severity', [fn('COUNT', col('severity')), 'count']],
      group: ['severity'],
      raw: true,
    });

    const sourceCounts = await Log.findAll({
      attributes: ['source', [fn('COUNT', col('source')), 'count']],
      group: ['source'],
      raw: true,
    });

    const topIps = await Alert.findAll({
      attributes: ['source_ip', [fn('COUNT', col('source_ip')), 'count']],
      where: literal('source_ip IS NOT NULL'),
      group: ['source_ip'],
      order: [[literal('count'), 'DESC']],
      limit: 5,
      raw: true,
    });

    const topRules = await Alert.findAll({
      attributes: ['rule_name', [fn('COUNT', col('rule_name')), 'count']],
      group: ['rule_name'],
      order: [[literal('count'), 'DESC']],
      limit: 5,
      raw: true,
    });

    res.render('dashboard', {
      title: 'Dashboard',
      stats: { totalEvents, totalAlerts, criticalAlerts, highAlerts, mediumAlerts, lowAlerts, openIncidents, maliciousIps, activeAssets, enabledRules },
      latestAlerts,
      latestLogs,
      latestIncidents,
      charts: {
        timeline: { labels: hourLabels, data: hourBuckets },
        severity: severityCounts,
        sources: sourceCounts,
        topIps,
        topRules,
      },
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load dashboard.', user: req.session.user });
  }
});

module.exports = router;


