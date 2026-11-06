/** Pure tests: log parsers, detection helpers, AbuseIPDB mapping, CSRF compare. No DB, no network. */
const fs = require('fs');
const path = require('path');
const {
  parseLogText, detectFormat, parseAuthLog, parseAccessLog, parseCsv, classifyRequest, parseSyslogTimestamp,
} = require('../services/logIngest');
const { isOffHours, extractCountry, countDistinct, isVolumeAnomaly } = require('../services/detectionHelpers');
const threatIntel = require('../services/threatIntel');
const { tokensMatch } = require('../middleware/csrf');
const { loadRuleDefs } = require('../services/ruleDefs');
const mitre = require('../services/mitre');

const NOW = new Date('2026-11-04T12:00:00Z');

describe('auth.log parser', () => {
  const sample = [
    'Nov  3 02:14:00 web01 sshd[811]: Failed password for root from 203.0.113.45 port 51500 ssh2',
    'Nov  3 02:14:09 web01 sshd[811]: Failed password for invalid user admin from 203.0.113.45 port 51501 ssh2',
    'Nov  3 02:20:00 web01 sshd[830]: Accepted publickey for alice from 192.168.1.20 port 50111 ssh2',
    'Nov  3 02:21:00 web01 sudo:   bob : user NOT in sudoers ; COMMAND=/bin/bash',
    'Nov  3 03:00:00 web01 CRON[901]: pam_unix(cron:session): session opened for user root',
    'garbage line',
  ].join('\n');

  test('extracts failed, accepted and sudo events; skips noise', () => {
    const r = parseAuthLog(sample, NOW);
    expect(r.events.map((e) => e.event_type)).toEqual([
      'FAILED_LOGIN', 'FAILED_LOGIN', 'SUCCESSFUL_LOGIN', 'PRIVILEGE_ESCALATION',
    ]);
    expect(r.skipped).toBe(2);
  });

  test('captures username, ip and host', () => {
    const e = parseAuthLog(sample, NOW).events[1];
    expect(e.username).toBe('admin');
    expect(e.source_ip).toBe('203.0.113.45');
    expect(e.hostname).toBe('web01');
    expect(e.source).toBe('Linux');
  });

  test('syslog timestamp without year resolves to a past date', () => {
    const d = parseSyslogTimestamp('Dec 30 10:00:00', NOW); // "Dec 30" is in the future for Nov 4 -> last year
    expect(d.getUTCFullYear()).toBe(2025);
    expect(parseSyslogTimestamp('Nov  3 02:14:00', NOW).getUTCFullYear()).toBe(2026);
  });

  test('ISO timestamps work', () => {
    const line = '2026-11-03T02:14:00.123456+00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2';
    const r = parseAuthLog(line, NOW);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].timestamp.toISOString().startsWith('2026-11-03T02:14:00')).toBe(true);
  });
});

describe('access log parser', () => {
  const log = [
    '192.168.1.50 - - [04/Nov/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 5120 "-" "Mozilla/5.0"',
    '45.33.32.156 - - [04/Nov/2026:10:00:10 +0000] "GET /p.php?id=1\'%20OR%20\'1\'=\'1 HTTP/1.1" 403 199 "-" "Mozilla/5.0"',
    '185.220.101.7 - - [04/Nov/2026:10:00:30 +0100] "GET /../../etc/passwd HTTP/1.1" 400 150 "-" "curl/8.0"',
    '10.0.0.5 - bob [04/Nov/2026:10:01:00 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"',
  ].join('\n');

  test('keeps attacks and 401s, ignores normal traffic', () => {
    const r = parseAccessLog(log);
    expect(r.events.map((e) => e.event_type)).toEqual(['WEB_ATTACK', 'WEB_ATTACK', 'FAILED_LOGIN']);
    expect(r.events[2].username).toBe('bob');
    expect(r.skipped).toBe(1);
  });

  test('timezone offset is applied', () => {
    const e = parseAccessLog(log).events[1];
    expect(e.timestamp.toISOString()).toBe('2026-11-04T09:00:30.000Z');
  });

  test('classifier labels common attack types', () => {
    expect(classifyRequest("/a?id=1 UNION SELECT password FROM users")).toBe('SQL injection');
    expect(classifyRequest('/x?q=<script>alert(1)</script>')).toBe('cross-site scripting');
    expect(classifyRequest('/..%2f..%2fetc/passwd')).toBe('path traversal');
    expect(classifyRequest('/ok', 'sqlmap/1.7')).toBe('scanner user-agent');
    expect(classifyRequest('/index.html', 'Mozilla/5.0')).toBeNull();
  });
});

describe('csv parser', () => {
  test('parses rows, quotes and country', () => {
    const csv = 'timestamp,event_type,severity,username,source_ip,message,country\n'
      + '2026-11-04T10:00:00Z,successful login,info,carol,1.2.3.4,"Login, via VPN",United Kingdom';
    const r = parseCsv(csv, NOW);
    expect(r.events).toHaveLength(1);
    expect(r.events[0].event_type).toBe('SUCCESSFUL_LOGIN');
    expect(r.events[0].message).toBe('Login, via VPN');
    expect(extractCountry(r.events[0])).toBe('united_kingdom');
  });

  test('rejects CSV without usable header', () => {
    expect(parseCsv('a,b\n1,2', NOW).error).toBeTruthy();
  });
});

describe('format detection + entry point', () => {
  test('detects each format', () => {
    expect(detectFormat('Nov  3 02:14:00 h sshd[1]: x')).toBe('auth');
    expect(detectFormat('1.2.3.4 - - [04/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1')).toBe('access');
    expect(detectFormat('timestamp,event_type,message\n1,2,3')).toBe('csv');
    expect(detectFormat('hello world')).toBeNull();
  });

  test('unknown format returns an error, not a throw', () => {
    expect(parseLogText('auto', 'hello world').error).toBeTruthy();
  });

  test('shipped sample files parse into events', () => {
    const dir = path.join(__dirname, '..', 'public', 'samples');
    const auth = parseLogText('auto', fs.readFileSync(path.join(dir, 'sample-auth.log'), 'utf8'));
    const access = parseLogText('auto', fs.readFileSync(path.join(dir, 'sample-access.log'), 'utf8'));
    const csv = parseLogText('auto', fs.readFileSync(path.join(dir, 'sample-events.csv'), 'utf8'));
    expect(auth.format).toBe('auth');
    expect(auth.events.length).toBeGreaterThan(15);
    expect(access.format).toBe('access');
    expect(access.events.length).toBeGreaterThan(3);
    expect(csv.format).toBe('csv');
    expect(csv.events).toHaveLength(2);
  });
});

describe('detection helpers', () => {
  test('off-hours', () => {
    expect(isOffHours('2026-11-04T02:00:00Z')).toBe(true);
    expect(isOffHours('2026-11-04T09:00:00Z')).toBe(false);
    expect(isOffHours('2026-11-04T20:00:00Z')).toBe(true);
  });

  test('countDistinct ignores blanks', () => {
    expect(countDistinct(['a', 'b', 'a', null, ''])).toBe(2);
  });

  test('volume anomaly needs many events AND far above peers', () => {
    expect(isVolumeAnomaly(60, [3, 4, 5, 2]).anomalous).toBe(true);
    expect(isVolumeAnomaly(10, [1, 1, 1, 1]).anomalous).toBe(false);      // below minEvents
    expect(isVolumeAnomaly(60, [50, 55, 40, 60]).anomalous).toBe(false);  // everyone is busy
    expect(isVolumeAnomaly(60, [3, 4]).anomalous).toBe(false);            // not enough peers
  });
});

describe('rule definitions', () => {
  test('every rule has a MITRE id that exists in the MITRE table', () => {
    const defs = Object.values(loadRuleDefs());
    expect(defs.length).toBeGreaterThanOrEqual(10);
    defs.forEach((d) => expect(mitre.getTechnique(d.mitre_id)).toBeTruthy());
  });

  test('threshold rules carry their parameters', () => {
    const defs = loadRuleDefs();
    expect(defs['brute-force'].threshold).toBe(5);
    expect(defs['password-spraying'].distinctUsers).toBe(5);
  });
});

describe('AbuseIPDB lookup', () => {
  const OLD = process.env.ABUSEIPDB_API_KEY;
  beforeEach(() => { process.env.ABUSEIPDB_API_KEY = 'test-key'; threatIntel.clearCache(); });
  afterAll(() => { if (OLD === undefined) delete process.env.ABUSEIPDB_API_KEY; else process.env.ABUSEIPDB_API_KEY = OLD; });

  const okFetch = (score) => async () => ({
    ok: true,
    json: async () => ({ data: { abuseConfidenceScore: score, countryCode: 'RU', totalReports: 7 } }),
  });

  test('maps score to verdict', async () => {
    expect((await threatIntel.lookup('8.8.4.4', { fetchImpl: okFetch(90) })).reputation).toBe('MALICIOUS');
    threatIntel.clearCache();
    expect((await threatIntel.lookup('8.8.4.4', { fetchImpl: okFetch(40) })).reputation).toBe('SUSPICIOUS');
    threatIntel.clearCache();
    expect((await threatIntel.lookup('8.8.4.4', { fetchImpl: okFetch(0) })).reputation).toBe('CLEAN');
  });

  test('falls back to local list when the API fails', async () => {
    const r = await threatIntel.lookup('203.0.113.45', { fetchImpl: async () => { throw new Error('down'); } });
    expect(r.provider).toBe('Local demo list');
    expect(r.reputation).toBe('MALICIOUS');
    expect(r.details).toContain('AbuseIPDB lookup failed');
  });

  test('private IPs never leave the machine', async () => {
    let called = false;
    await threatIntel.lookup('192.168.1.5', { fetchImpl: async () => { called = true; return okFetch(99)(); } });
    expect(called).toBe(false);
  });

  test('results are cached', async () => {
    let calls = 0;
    const f = async () => { calls++; return okFetch(10)(); };
    await threatIntel.lookup('8.8.8.8', { fetchImpl: f });
    await threatIntel.lookup('8.8.8.8', { fetchImpl: f });
    expect(calls).toBe(1);
  });
});

describe('csrf token comparison', () => {
  test('matches only identical strings', () => {
    expect(tokensMatch('abc', 'abc')).toBe(true);
    expect(tokensMatch('abc', 'abd')).toBe(false);
    expect(tokensMatch('abc', 'abcd')).toBe(false);
    expect(tokensMatch(undefined, 'abc')).toBe(false);
  });
});
