/**
 * Unit tests for the pure logic pieces (no DB, no network).
 * Run with: npm test
 */
const { calculateRisk } = require('../services/riskEngine');
const { parseEvent } = require('../services/logParser');
const simulator = require('../services/simulator');
const mitre = require('../services/mitre');
const threatIntel = require('../services/threatIntel');

describe('riskEngine', () => {
  test('CRITICAL severity scores 40', () => {
    const r = calculateRisk({ severity: 'CRITICAL' });
    expect(r.score).toBe(40);
    expect(r.band).toBe('Medium');
  });

  test('repeated events add 10', () => {
    const r = calculateRisk({ severity: 'HIGH', repeatedEvents: true });
    expect(r.score).toBe(40);
  });

  test('score is capped at 100', () => {
    const r = calculateRisk({
      severity: 'CRITICAL', repeatedEvents: true,
      threatIntelMalicious: true, criticalAsset: true,
    });
    expect(r.score).toBe(90);
  });

  test('explanation lists each contributing factor', () => {
    const r = calculateRisk({ severity: 'HIGH', repeatedEvents: true });
    expect(r.explanation.length).toBe(2);
  });
});

describe('logParser', () => {
  test('fills defaults for missing fields', () => {
    const parsed = parseEvent({ message: 'test' });
    expect(parsed.source).toBe('Unknown');
    expect(parsed.event_type).toBe('GENERIC_EVENT');
    expect(parsed.severity).toBe('INFO');
  });

  test('normalizes severity casing', () => {
    expect(parseEvent({ severity: 'critical', message: 'x' }).severity).toBe('CRITICAL');
  });

  test('rejects invalid severity, falls back to INFO', () => {
    expect(parseEvent({ severity: 'BOGUS', message: 'x' }).severity).toBe('INFO');
  });
});

describe('simulator', () => {
  test('brute force generates 5 or more events from one IP', () => {
    const events = simulator.generate('brute-force');
    expect(events.length).toBeGreaterThanOrEqual(5);
    const ips = new Set(events.map((e) => e.source_ip));
    expect(ips.size).toBe(1);
    expect(events[0].event_type).toBe('FAILED_LOGIN');
  });

  test('port scan hits many ports from one IP', () => {
    const events = simulator.generate('port-scan');
    expect(events.length).toBeGreaterThanOrEqual(6);
    expect(events[0].event_type).toBe('PORT_SCAN');
  });

  test('powershell event contains a suspicious keyword', () => {
    const [event] = simulator.generate('suspicious-powershell');
    const hay = `${event.message} ${event.raw_log}`;
    const hit = ['EncodedCommand', 'DownloadString', 'Invoke-WebRequest'].some((k) => hay.includes(k));
    expect(hit).toBe(true);
  });

  test('malware and privilege escalation are CRITICAL', () => {
    expect(simulator.generate('malware')[0].severity).toBe('CRITICAL');
    expect(simulator.generate('privilege-escalation')[0].severity).toBe('CRITICAL');
  });

  test('unknown type throws', () => {
    expect(() => simulator.generate('nope')).toThrow();
  });
});

describe('mitre', () => {
  test('known technique resolves', () => {
    expect(mitre.getTechnique('T1110').name).toBe('Brute Force');
  });
  test('unknown technique returns null', () => {
    expect(mitre.getTechnique('T9999')).toBeNull();
  });
});

describe('threatIntel', () => {
  test('detects indicator types', () => {
    expect(threatIntel.detectIndicatorType('8.8.8.8')).toBe('IP');
    expect(threatIntel.detectIndicatorType('example.com')).toBe('DOMAIN');
    expect(threatIntel.detectIndicatorType('d41d8cd98f00b204e9800998ecf8427e')).toBe('HASH');
    expect(threatIntel.detectIndicatorType('!!!')).toBeNull();
  });

  test('flags demo attacker IPs as malicious', async () => {
    const r = await threatIntel.lookup('203.0.113.45');
    expect(r.reputation).toBe('MALICIOUS');
  });

  test('treats private ranges as clean', async () => {
    const r = await threatIntel.lookup('192.168.1.10');
    expect(r.reputation).toBe('CLEAN');
  });

  test('returns an error for garbage input', async () => {
    const r = await threatIntel.lookup('not an indicator!!');
    expect(r.error).toBeTruthy();
  });
});
