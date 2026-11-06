/**
 * pipeline.js - the ONE path every event takes, whether it came from the
 * simulator, an uploaded log file, or demo seeding:
 *
 *   raw events -> parseEvent -> save -> detection engine -> alerts -> live push
 */
const { parseEvent } = require('./logParser');
const detectionEngine = require('./detectionEngine');

const CHUNK = 200;      // keeps SQLite bulk inserts well under the variable limit
const EMIT_LOG_LIMIT = 50;
const EMIT_ALERT_LIMIT = 20;

async function processEvents({ models, io }, rawEvents) {
  const { Log, Rule, Alert } = models;

  // Chronological order so ids ascend with time and windows behave.
  const parsed = rawEvents
    .map(parseEvent)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const savedLogs = [];
  for (let i = 0; i < parsed.length; i += CHUNK) {
    savedLogs.push(...(await Log.bulkCreate(parsed.slice(i, i + CHUNK))));
  }

  const rules = await Rule.findAll({ where: { enabled: true } });
  const newAlerts = [];
  for (const log of savedLogs) {
    const alerts = await detectionEngine.evaluateLog({ Log, Rule, Alert, rules }, log);
    newAlerts.push(...alerts);
  }

  if (io) {
    // Don't flood browsers when a big file is imported.
    savedLogs.slice(0, EMIT_LOG_LIMIT).forEach((l) => io.emit('new_log', l.toJSON()));
    newAlerts.slice(0, EMIT_ALERT_LIMIT).forEach((a) => io.emit('new_alert', a.toJSON()));
  }

  return { savedLogs, newAlerts };
}

module.exports = { processEvents };
