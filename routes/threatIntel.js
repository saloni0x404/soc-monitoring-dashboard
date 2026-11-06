const express = require('express');
const { ThreatIntel, AuditLog } = require('../models');
const { requireAuth } = require('../middleware/auth');
const threatIntel = require('../services/threatIntel');

const router = express.Router();

router.get('/threat-intel', requireAuth, async (req, res) => {
  try {
    const recent = await ThreatIntel.findAll({ order: [['checked_at', 'DESC']], limit: 25 });
    res.render('threat-intel', {
      title: 'Threat Intelligence',
      recent,
      result: null,
      query: '',
      providers: threatIntel.configuredProviders(),
    });
  } catch (err) {
    console.error('Threat intel page error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Could not load threat intelligence.', user: req.session.user });
  }
});

router.post('/threat-intel/lookup', requireAuth, async (req, res) => {
  const query = (req.body.indicator || '').trim();
  try {
    const result = await threatIntel.lookup(query);

    if (!result.error) {
      await ThreatIntel.create({
        indicator: result.indicator,
        indicator_type: result.indicator_type,
        reputation: result.reputation,
        country: result.country,
        provider: result.provider,
        details: result.details,
        checked_at: new Date(),
      }).catch(() => {});

      await AuditLog.create({
        user_id: req.session.user.id,
        action: 'THREAT_INTEL_LOOKUP',
        target: result.indicator,
        ip: req.ip,
      }).catch(() => {});
    }

    const recent = await ThreatIntel.findAll({ order: [['checked_at', 'DESC']], limit: 25 });

    res.render('threat-intel', {
      title: 'Threat Intelligence',
      recent,
      result,
      query,
      providers: threatIntel.configuredProviders(),
    });
  } catch (err) {
    console.error('Threat intel lookup error:', err);
    res.status(500).render('error', { title: 'Server Error', message: 'Lookup failed.', user: req.session.user });
  }
});

module.exports = router;
