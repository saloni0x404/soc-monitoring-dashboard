const test = require('node:test');
const assert = require('node:assert');
const E = require('../engine');
const on = Object.fromEntries(E.RULES.map((r) => [r.id, true]));

function run(type) {
  const db = { logs: [] }, hits = [];
  E.sim(type).forEach((l) => { db.logs.push(l); E.detect(db, l, on).forEach((h) => hits.push(h[0])); });
  return hits;
}
test('every simulator triggers its matching rule', () => {
  for (const t of ['brute_force', 'port_scan', 'powershell', 'priv_esc', 'malware', 'web_attack']) assert.ok(run(t).includes(t), t);
});
test('risk score adds up and is capped at 100', () => {
  assert.equal(E.risk('Critical', true, { verdict: 'Malicious' }, 'Server-01').score, 90);
  assert.equal(E.risk('Low', false, { verdict: 'Clean' }, 'x').score, 5);
});
test('known bad IP is malicious', () => assert.equal(E.intel('203.0.113.45').verdict, 'Malicious'));
test('asset criticality overrides the host name guess', () => {
  assert.equal(E.risk('High', false, { verdict: 'Clean' }, 'anything', true).score, 40);
  assert.equal(E.risk('High', false, { verdict: 'Clean' }, 'Server-01', false).score, 30);
});
test('every rule has response guidance', () => E.RULES.forEach((r) => assert.ok(E.REC[r.id].length >= 3, r.id)));
test('ambient traffic never triggers a rule', () => {
  const db = { logs: [] };
  for (let i = 0; i < 300; i++) { const l = E.ambient(); db.logs.push(l); assert.equal(E.detect(db, l, on).length, 0); }
});
