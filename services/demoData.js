/**
 * demoData.js - fills an empty database with a believable set of events so a
 * fresh deployment (or a recruiter opening the link) sees a working
 * dashboard instead of empty tables. Uses the same pipeline as real data,
 * so the alerts you see are genuinely produced by the detection engine.
 */
const simulator = require('./simulator');
const { processEvents } = require('./pipeline');

const DEMO_SEQUENCE = [
  'brute-force', 'port-scan', 'suspicious-powershell', 'privilege-escalation',
  'malware', 'suspicious-login', 'web-attack', 'web-attack', 'brute-force',
];

async function seedDemoData({ models, io }, { force = false } = {}) {
  if (!force && (await models.Log.count()) > 0) return { seeded: false };

  let logs = 0;
  let alerts = 0;
  for (const type of DEMO_SEQUENCE) {
    const r = await processEvents({ models, io }, simulator.generate(type));
    logs += r.savedLogs.length;
    alerts += r.newAlerts.length;
  }
  console.log(`Demo data seeded: ${logs} logs, ${alerts} alerts.`);
  return { seeded: true, logs, alerts };
}

module.exports = { seedDemoData, DEMO_SEQUENCE };
