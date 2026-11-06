/**
 * detectionEngine.js
 *
 * Runs after a log is saved. Checks the log against every enabled rule and
 * creates an Alert when one matches.
 *
 *  - Threshold rules (brute-force, port-scan, password-spraying,
 *    impossible-travel) look at recent logs around THIS log's timestamp.
 *    Anchoring to the log's own time (not "now") means uploaded historical
 *    log files are analysed correctly.
 *  - Immediate rules match on the single event itself.
 *  - The anomaly rule compares one IP's event volume to every other IP.
 *
 * Rule parameters (thresholds, windows, keywords) come from rules/*.json via
 * ruleDefs.getRuleConfig(); the DB only stores metadata + the enabled flag.
 *
 * Dedup: threshold/anomaly rules skip creating a new alert when an OPEN
 * alert for the same rule + source IP already exists.
 */

const { Op, fn, col } = require('sequelize');
const { calculateRisk } = require('./riskEngine');
const { getRuleConfig } = require('./ruleDefs');
const threatIntel = require('./threatIntel');
const {
  isOffHours, extractCountry, countDistinct, isVolumeAnomaly,
} = require('./detectionHelpers');

const OPEN_STATUSES = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'];

function timeWindow(log, ms) {
  const ts = new Date(log.timestamp);
  return { [Op.gte]: new Date(ts.getTime() - ms), [Op.lte]: ts };
}

async function hasOpenAlert(Alert, ruleName, sourceIp) {
  if (!sourceIp) return false;
  const existing = await Alert.findOne({
    where: { rule_name: ruleName, source_ip: sourceIp, status: { [Op.in]: OPEN_STATUSES } },
  });
  return !!existing;
}

async function createAlert(Alert, { rule, log, repeatedEvents, relatedLogIds, extraNote }) {
  // Threat-intel bonus: AbuseIPDB when configured, local demo list otherwise.
  let threatIntelMalicious = false;
  if (log.source_ip) {
    try {
      const ti = await threatIntel.lookup(log.source_ip);
      threatIntelMalicious = ti.reputation === 'MALICIOUS';
    } catch (e) { /* intel is a bonus, never block an alert */ }
  }

  const { score, explanation } = calculateRisk({
    severity: rule.severity,
    repeatedEvents,
    threatIntelMalicious,
  });
  if (extraNote) explanation.push(extraNote);

  return Alert.create({
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    risk_score: score,
    source_ip: log.source_ip,
    username: log.username,
    hostname: log.hostname,
    rule_name: rule.name,
    mitre_id: rule.mitre_id,
    status: 'NEW',
    related_log_ids: JSON.stringify(relatedLogIds || [log.id]),
    risk_explanation: explanation.join('; '),
  });
}

// ---- Threshold rules ----

async function checkBruteForce({ Log, Alert, log, rule }) {
  if (log.event_type !== 'FAILED_LOGIN' || !log.source_ip) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const recent = await Log.findAll({
    where: {
      event_type: 'FAILED_LOGIN',
      source_ip: log.source_ip,
      timestamp: timeWindow(log, (rule.windowMinutes || 5) * 60 * 1000),
    },
    order: [['timestamp', 'ASC']],
  });

  if (recent.length >= (rule.threshold || 5)) {
    return createAlert(Alert, { rule, log, repeatedEvents: true, relatedLogIds: recent.map((l) => l.id) });
  }
  return null;
}

async function checkPortScan({ Log, Alert, log, rule }) {
  if (log.event_type !== 'PORT_SCAN' || !log.source_ip) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const recent = await Log.findAll({
    where: {
      event_type: 'PORT_SCAN',
      source_ip: log.source_ip,
      timestamp: timeWindow(log, (rule.windowSeconds || 30) * 1000),
    },
    order: [['timestamp', 'ASC']],
  });

  if (recent.length >= (rule.threshold || 6)) {
    return createAlert(Alert, { rule, log, repeatedEvents: true, relatedLogIds: recent.map((l) => l.id) });
  }
  return null;
}

async function checkPasswordSpraying({ Log, Alert, log, rule }) {
  if (log.event_type !== 'FAILED_LOGIN' || !log.source_ip || !log.username) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const recent = await Log.findAll({
    where: {
      event_type: 'FAILED_LOGIN',
      source_ip: log.source_ip,
      timestamp: timeWindow(log, (rule.windowMinutes || 10) * 60 * 1000),
    },
    order: [['timestamp', 'ASC']],
  });

  const distinct = countDistinct(recent.map((l) => l.username));
  if (distinct >= (rule.distinctUsers || 5)) {
    return createAlert(Alert, {
      rule, log, repeatedEvents: true, relatedLogIds: recent.map((l) => l.id),
      extraNote: `${distinct} different usernames tried from one IP`,
    });
  }
  return null;
}

async function checkImpossibleTravel({ Log, Alert, log, rule }) {
  // Simulator events carry an explicit flag.
  if (log.event_type === 'SUSPICIOUS_LOGIN' && /flag=impossible_travel/.test(log.raw_log || '')) {
    return createAlert(Alert, { rule, log, repeatedEvents: false });
  }
  if (log.event_type !== 'SUCCESSFUL_LOGIN' || !log.username) return null;
  const here = extractCountry(log);
  if (!here) return null;

  const others = await Log.findAll({
    where: {
      event_type: { [Op.in]: ['SUCCESSFUL_LOGIN', 'SUSPICIOUS_LOGIN'] },
      username: log.username,
      id: { [Op.ne]: log.id },
      timestamp: timeWindow(log, (rule.windowMinutes || 60) * 60 * 1000),
    },
  });
  const other = others.find((l) => {
    const c = extractCountry(l);
    return c && c !== here;
  });
  if (!other) return null;

  return createAlert(Alert, {
    rule, log, repeatedEvents: false, relatedLogIds: [other.id, log.id],
    extraNote: `Logins from ${extractCountry(other)} and ${here} within ${rule.windowMinutes || 60} min`,
  });
}

async function checkIpVolumeAnomaly({ Log, Alert, log, rule }) {
  if (!log.source_ip) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;

  const rows = await Log.findAll({
    attributes: ['source_ip', [fn('COUNT', col('id')), 'c']],
    where: {
      source_ip: { [Op.ne]: null },
      timestamp: timeWindow(log, (rule.windowMinutes || 10) * 60 * 1000),
    },
    group: ['source_ip'],
    raw: true,
  });

  const mine = rows.find((r) => r.source_ip === log.source_ip);
  if (!mine) return null;
  const others = rows.filter((r) => r.source_ip !== log.source_ip).map((r) => Number(r.c));
  const { anomalous, mean } = isVolumeAnomaly(Number(mine.c), others, rule);
  if (!anomalous) return null;

  return createAlert(Alert, {
    rule, log, repeatedEvents: true,
    extraNote: `${mine.c} events vs. average ${mean.toFixed(1)} for other IPs`,
  });
}

// ---- Immediate rules ----

async function checkSuspiciousPowerShell({ Alert, log, rule }) {
  if (log.event_type !== 'SUSPICIOUS_POWERSHELL') return null;
  const haystack = `${log.message} ${log.raw_log}`;
  if (!(rule.keywords || []).some((kw) => haystack.includes(kw))) return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkPrivilegeEscalation({ Alert, log, rule }) {
  if (log.event_type !== 'PRIVILEGE_ESCALATION') return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkMalware({ Alert, log, rule }) {
  if (log.event_type !== 'MALWARE_DETECTED') return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkWebAttack({ Alert, log, rule }) {
  if (log.event_type !== 'WEB_ATTACK') return null;
  return createAlert(Alert, { rule, log, repeatedEvents: false });
}

async function checkOffHoursLogin({ Alert, log, rule }) {
  if (log.event_type !== 'SUCCESSFUL_LOGIN') return null;
  if (!isOffHours(log.timestamp, rule.workStartHour, rule.workEndHour)) return null;
  if (await hasOpenAlert(Alert, rule.name, log.source_ip)) return null;
  return createAlert(Alert, {
    rule, log, repeatedEvents: false,
    extraNote: `Login at ${new Date(log.timestamp).getUTCHours()}:00 UTC, outside working hours`,
  });
}

const RULE_CHECKS = {
  'brute-force': checkBruteForce,
  'port-scan': checkPortScan,
  'password-spraying': checkPasswordSpraying,
  'impossible-travel': checkImpossibleTravel,
  'ip-volume-anomaly': checkIpVolumeAnomaly,
  'suspicious-powershell': checkSuspiciousPowerShell,
  'privilege-escalation': checkPrivilegeEscalation,
  'malware': checkMalware,
  'web-attack': checkWebAttack,
  'off-hours-login': checkOffHoursLogin,
};

/**
 * Evaluates one saved Log against all enabled rules.
 * @param {object} models - { Log, Rule, Alert, rules? }  (rules = preloaded enabled
 *                          Rule rows, so bulk imports don't re-query for every log)
 */
async function evaluateLog(models, log) {
  const { Log, Rule, Alert } = models;
  const rules = models.rules || (await Rule.findAll({ where: { enabled: true } }));
  const created = [];

  for (const dbRule of rules) {
    const check = RULE_CHECKS[dbRule.name];
    if (!check) continue;
    const rule = getRuleConfig(dbRule);
    try {
      const alert = await check({ Log, Alert, log, rule });
      if (alert) created.push(alert);
    } catch (err) {
      console.error(`Detection engine error running rule "${dbRule.name}":`, err);
    }
  }
  return created;
}

module.exports = { evaluateLog, RULE_CHECKS };
