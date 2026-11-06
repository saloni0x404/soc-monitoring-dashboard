/**
 * threatIntel.js
 *
 * Provider abstraction for threat intelligence lookups.
 * All providers are OPTIONAL - if no API keys are configured in .env,
 * lookups return a clear "not configured" result instead of throwing,
 * so the dashboard keeps working normally.
 *
 * API keys are read from process.env only and are NEVER sent to the browser.
 */

const PROVIDERS = {
  virustotal: {
    name: 'VirusTotal',
    envKey: 'VIRUSTOTAL_API_KEY',
    supports: ['IP', 'DOMAIN', 'HASH'],
  },
  abuseipdb: {
    name: 'AbuseIPDB',
    envKey: 'ABUSEIPDB_API_KEY',
    supports: ['IP'],
  },
  otx: {
    name: 'AlienVault OTX',
    envKey: 'OTX_API_KEY',
    supports: ['IP', 'DOMAIN', 'HASH'],
  },
};

function detectIndicatorType(indicator) {
  const value = (indicator || '').trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return 'IP';
  if (/^[a-fA-F0-9]{32}$/.test(value) || /^[a-fA-F0-9]{40}$/.test(value) || /^[a-fA-F0-9]{64}$/.test(value)) return 'HASH';
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'DOMAIN';
  return null;
}

function configuredProviders() {
  return Object.entries(PROVIDERS)
    .filter(([, p]) => !!process.env[p.envKey])
    .map(([key, p]) => ({ key, name: p.name }));
}

/**
 * Local heuristic fallback used when no external provider is configured.
 * Flags the synthetic "attacker pool" IPs the simulator uses, so the
 * demo still shows a meaningful malicious/clean verdict offline.
 */
const KNOWN_BAD_DEMO_IPS = ['203.0.113.45', '198.51.100.23', '45.33.32.156', '185.220.101.7'];

function localHeuristic(indicator, type) {
  if (type === 'IP' && KNOWN_BAD_DEMO_IPS.includes(indicator)) {
    return {
      reputation: 'MALICIOUS',
      country: 'Unknown',
      provider: 'Local demo list',
      details: 'This IP appears in the simulator\'s synthetic attacker pool. Flagged for demonstration purposes only - it is not a real-world threat indicator.',
    };
  }
  if (type === 'IP' && indicator.startsWith('192.168.')) {
    return {
      reputation: 'CLEAN',
      country: 'Private range',
      provider: 'Local demo list',
      details: 'RFC1918 private address - internal host, not routable on the public internet.',
    };
  }
  return {
    reputation: 'UNKNOWN',
    country: null,
    provider: 'Local demo list',
    details: 'No external threat intelligence provider is configured, and this indicator is not in the local demo list.',
  };
}

// ---- AbuseIPDB (real lookups) ----

const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour - free tier is only 1000 checks/day
const CACHE_MAX = 500;
const cache = new Map();

function isPrivateIp(ip) {
  return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || ip === '0.0.0.0';
}

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > CACHE_TTL_MS) { cache.delete(key); return null; }
  return hit.value;
}

function cacheSet(key, value) {
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
  cache.set(key, { at: Date.now(), value });
}

function clearCache() { cache.clear(); }

/** Maps AbuseIPDB's 0-100 confidence score to our verdicts. */
function scoreToReputation(score) {
  if (score >= 75) return 'MALICIOUS';
  if (score >= 25) return 'SUSPICIOUS';
  return 'CLEAN';
}

async function fetchAbuseIpdb(ip, fetchImpl = fetch) {
  const url = `${ABUSEIPDB_URL}?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
  const res = await fetchImpl(url, {
    headers: { Key: process.env.ABUSEIPDB_API_KEY, Accept: 'application/json' },
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`AbuseIPDB returned HTTP ${res.status}`);
  const body = await res.json();
  const d = body && body.data;
  if (!d || typeof d.abuseConfidenceScore !== 'number') throw new Error('Unexpected AbuseIPDB response');
  return {
    reputation: scoreToReputation(d.abuseConfidenceScore),
    country: d.countryCode || null,
    provider: 'AbuseIPDB',
    abuse_score: d.abuseConfidenceScore,
    total_reports: d.totalReports || 0,
    details: `Abuse confidence ${d.abuseConfidenceScore}/100 from ${d.totalReports || 0} report(s) in the last 90 days${d.isp ? ` (ISP: ${d.isp})` : ''}.`,
  };
}

/**
 * Looks up an indicator. For public IPs with ABUSEIPDB_API_KEY set, calls
 * AbuseIPDB (cached 1h). Any failure falls back to the local demo list so
 * the dashboard never breaks because a third-party API is down.
 *
 * @param {string} indicator
 * @param {{fetchImpl?: Function}} [opts] fetchImpl lets tests inject a fake fetch
 */
async function lookup(indicator, opts = {}) {
  const value = (indicator || '').trim();
  const type = detectIndicatorType(value);

  if (!type) {
    return {
      error: 'Unrecognized indicator. Enter a valid IP address, domain, or file hash (MD5/SHA1/SHA256).',
    };
  }

  const available = configuredProviders();
  let result = null;
  let fallbackNote = '';

  if (type === 'IP' && process.env.ABUSEIPDB_API_KEY && !isPrivateIp(value)) {
    result = cacheGet(value);
    if (!result) {
      try {
        result = await fetchAbuseIpdb(value, opts.fetchImpl);
        cacheSet(value, result);
      } catch (err) {
        fallbackNote = ` (AbuseIPDB lookup failed: ${err.message}; showing local result.)`;
      }
    }
  }

  if (!result) {
    result = localHeuristic(value, type);
    result = { ...result, details: result.details + fallbackNote };
  }

  return {
    indicator: value,
    indicator_type: type,
    reputation: result.reputation,
    country: result.country,
    provider: result.provider,
    details: result.details,
    abuse_score: result.abuse_score,
    total_reports: result.total_reports,
    configured: available.length > 0,
    availableProviders: available,
  };
}

module.exports = {
  lookup, detectIndicatorType, configuredProviders, PROVIDERS, KNOWN_BAD_DEMO_IPS,
  fetchAbuseIpdb, scoreToReputation, isPrivateIp, clearCache,
};
