/**
 * ruleDefs.js
 *
 * Loads rules/*.json once. The JSON files hold both the rule metadata
 * (title, severity, MITRE id) AND the tunable parameters (threshold,
 * window, keywords). The database only stores the metadata + enabled flag,
 * so the detection engine merges the two through getRuleConfig().
 */
const fs = require('fs');
const path = require('path');

const RULES_DIR = path.join(__dirname, '..', 'rules');
let cache = null;

function loadRuleDefs() {
  if (cache) return cache;
  cache = {};
  for (const file of fs.readdirSync(RULES_DIR).filter((f) => f.endsWith('.json'))) {
    const def = JSON.parse(fs.readFileSync(path.join(RULES_DIR, file), 'utf-8'));
    cache[def.name] = def;
  }
  return cache;
}

/** DB row (enabled/severity/title) layered over the JSON defaults (parameters). */
function getRuleConfig(rule) {
  const def = loadRuleDefs()[rule.name] || {};
  const plain = typeof rule.toJSON === 'function' ? rule.toJSON() : rule;
  return { ...def, ...plain };
}

module.exports = { loadRuleDefs, getRuleConfig };
