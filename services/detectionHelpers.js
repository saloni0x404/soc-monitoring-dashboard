/**
 * detectionHelpers.js - small PURE functions used by the detection engine.
 * No database access, so they are trivial to unit test.
 */

/** Hours [start, end) are "working hours" (UTC). Anything else is off-hours. */
function isOffHours(date, startHour = 7, endHour = 20) {
  const h = new Date(date).getUTCHours();
  return h < startHour || h >= endHour;
}

/** Pulls "geo=Russia" / "country=RU" out of a log's raw text. */
function extractCountry(log) {
  const text = `${log.raw_log || ''} ${log.message || ''}`;
  const m = text.match(/\b(?:geo|country)=([A-Za-z_-]{2,40})/i);
  return m ? m[1].toLowerCase() : null;
}

function countDistinct(values) {
  return new Set(values.filter((v) => v !== null && v !== undefined && v !== '')).size;
}

/**
 * Simple statistical anomaly check: is this IP's event count far above
 * what the OTHER IPs in the same window are doing?
 * @param {number} ipCount - events from the IP being checked
 * @param {number[]} otherCounts - event counts of all other IPs in the window
 */
function isVolumeAnomaly(ipCount, otherCounts, { minEvents = 25, multiplier = 5, minPeers = 3 } = {}) {
  if (otherCounts.length < minPeers) return { anomalous: false, mean: 0 };
  const mean = otherCounts.reduce((a, b) => a + b, 0) / otherCounts.length;
  const anomalous = ipCount >= minEvents && ipCount >= multiplier * Math.max(mean, 1);
  return { anomalous, mean };
}

module.exports = { isOffHours, extractCountry, countDistinct, isVolumeAnomaly };
