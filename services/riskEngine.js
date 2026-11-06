/**
 * riskEngine.js
 *
 * Calculates a simple, explainable 0-100 risk score for an alert.
 * Deliberately simple additive model per the "avoid over-engineering"
 * brief - easy to read, easy to justify to an interviewer or teammate.
 */

const SEVERITY_POINTS = {
  CRITICAL: 40,
  HIGH: 30,
  MEDIUM: 15,
  LOW: 5,
};

const REPEATED_EVENTS_BONUS = 10;
const THREAT_INTEL_MALICIOUS_BONUS = 30; // wired up in Step 5
const CRITICAL_ASSET_BONUS = 10; // wired up once Assets criticality is used

const MAX_SCORE = 100;

/**
 * @param {object} context
 * @param {string} context.severity - CRITICAL | HIGH | MEDIUM | LOW
 * @param {boolean} [context.repeatedEvents] - true if this is a repeated/burst pattern (e.g. brute force)
 * @param {boolean} [context.threatIntelMalicious] - true if source IP is known-bad (Step 5)
 * @param {boolean} [context.criticalAsset] - true if the target host is marked critical (Step 2 Assets)
 * @returns {{ score: number, band: string, explanation: string[] }}
 */
function calculateRisk(context) {
  const explanation = [];
  let score = 0;

  const basePoints = SEVERITY_POINTS[context.severity] || 0;
  score += basePoints;
  explanation.push(`${context.severity} severity: +${basePoints}`);

  if (context.repeatedEvents) {
    score += REPEATED_EVENTS_BONUS;
    explanation.push(`Repeated events pattern: +${REPEATED_EVENTS_BONUS}`);
  }

  if (context.threatIntelMalicious) {
    score += THREAT_INTEL_MALICIOUS_BONUS;
    explanation.push(`Source IP flagged malicious by threat intel: +${THREAT_INTEL_MALICIOUS_BONUS}`);
  }

  if (context.criticalAsset) {
    score += CRITICAL_ASSET_BONUS;
    explanation.push(`Target asset marked critical: +${CRITICAL_ASSET_BONUS}`);
  }

  score = Math.min(score, MAX_SCORE);

  let band;
  if (score >= 80) band = 'Critical';
  else if (score >= 60) band = 'High';
  else if (score >= 30) band = 'Medium';
  else band = 'Low';

  return { score, band, explanation };
}

module.exports = { calculateRisk, SEVERITY_POINTS, MAX_SCORE };
