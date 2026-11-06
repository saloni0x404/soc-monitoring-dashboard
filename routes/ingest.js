const express = require('express');
const models = require('../models');
const { requireRole } = require('../middleware/auth');
const { parseLogText } = require('../services/logIngest');
const { processEvents } = require('../services/pipeline');

const router = express.Router();
const MAX_CHARS = 1500000; // ~1.5 MB of text

router.get('/ingest', requireRole('ADMIN', 'ANALYST'), (req, res) => {
  res.render('ingest', { title: 'Import Logs' });
});

// The browser reads the chosen file as text and sends it as JSON.
router.post('/ingest', requireRole('ADMIN', 'ANALYST'), async (req, res) => {
  const { format, content, filename } = req.body || {};

  if (typeof content !== 'string' || !content.trim()) {
    return res.status(400).json({ error: 'No log content received.' });
  }
  if (content.length > MAX_CHARS) {
    return res.status(413).json({ error: 'File too large (limit about 1.5 MB). Split it and upload in parts.' });
  }
  if (format && !['auto', 'auth', 'access', 'csv'].includes(format)) {
    return res.status(400).json({ error: 'Unknown format.' });
  }

  try {
    const parsed = parseLogText(format || 'auto', content);
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    if (parsed.events.length === 0) {
      return res.status(422).json({
        error: `No security-relevant events found (${parsed.skipped} line(s) skipped). Check the format selection.`,
      });
    }

    const { savedLogs, newAlerts } = await processEvents({ models, io: req.app.get('io') }, parsed.events);

    await models.AuditLog.create({
      user_id: req.session.user.id,
      action: 'LOGS_IMPORTED',
      target: `${String(filename || 'pasted text').slice(0, 80)} (${parsed.format}, ${savedLogs.length} events)`,
      ip: req.ip,
    }).catch(() => {});

    return res.json({
      success: true,
      format: parsed.format,
      imported: savedLogs.length,
      skipped: parsed.skipped,
      truncated: parsed.truncated,
      alertsCreated: newAlerts.length,
      message: `Imported ${savedLogs.length} event(s) from ${parsed.format} log, ${newAlerts.length} alert(s) created`
        + (parsed.truncated ? ' (stopped at the 2000-event limit)' : '') + '.',
    });
  } catch (err) {
    console.error('Ingest error:', err);
    return res.status(500).json({ error: 'Failed to import logs.' });
  }
});

module.exports = router;
