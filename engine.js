// Detection rules, risk scoring, threat-intel demo lookup and the synthetic event simulator.
// No dependencies, so it is easy to unit test.
const RULES = [
  { id: 'brute_force', title: 'Brute Force Login', short: 'Brute Force', sev: 'High', mitre: 'T1110', desc: '5+ failed logins from one IP within 5 minutes' },
  { id: 'port_scan', title: 'Port Scan Detected', short: 'Port Scan', sev: 'High', mitre: 'T1046', desc: '6+ port contacts from one IP within 30 seconds' },
  { id: 'powershell', title: 'Suspicious PowerShell', short: 'PowerShell', sev: 'High', mitre: 'T1059.001', desc: 'EncodedCommand, DownloadString or Invoke-WebRequest in a command line' },
  { id: 'priv_esc', title: 'Privilege Escalation', short: 'Priv. Esc.', sev: 'Critical', mitre: 'T1068', desc: 'User added to the Administrators group' },
  { id: 'malware', title: 'Malware Detected', short: 'Malware', sev: 'Critical', mitre: 'T1204', desc: 'Antivirus signature match' },
  { id: 'web_attack', title: 'Web Attack (SQLi/XSS)', short: 'Web Attack', sev: 'Medium', mitre: 'T1190', desc: 'SQL injection, XSS or path traversal pattern in a request' },
];
const BAD = new Set(['203.0.113.45', '198.51.100.23', '192.0.2.99']);
const BASE = { Critical: 40, High: 30, Medium: 15, Low: 5 };
const CRIT_ASSET = /server-01|domain controller|auth server/i;
const HOSTS = ['Server-01', 'Endpoint-247', 'Auth Server', 'Domain Controller', 'Web Server', 'Endpoint-112'];
const pick = (a) => a[Math.floor(Math.random() * a.length)];

const REC = {
  brute_force: ['Block or rate-limit the source IP at the firewall', 'Force a password reset for the targeted accounts', 'Enable MFA on exposed login endpoints'],
  port_scan: ['Block the scanning IP at the perimeter', 'Check which of the probed ports are actually open', 'Close or restrict any unneeded services'],
  powershell: ['Isolate the endpoint from the network', 'Collect the full command line and parent process', 'Review scheduled tasks and startup items for persistence'],
  priv_esc: ['Confirm the change with the account owner', 'Remove the account from Administrators if it was not approved', 'Review that account\'s recent logins'],
  malware: ['Quarantine the file and isolate the host', 'Run a full scan on the host', 'Search other hosts for the same signature'],
  web_attack: ['Block the source IP at the web application firewall', 'Check application logs for successful requests', 'Fix the vulnerable endpoint with input validation'],
};

function intel(ip) {
  if (BAD.has(ip)) return { ip, verdict: 'Malicious', score: 92, reports: 214, country: 'Unknown' };
  if (/^(10\.|192\.168\.|127\.)/.test(ip)) return { ip, verdict: 'Clean', score: 0, reports: 0, country: 'Internal' };
  let h = 0;
  for (const c of ip) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const s = h % 40;
  return { ip, verdict: s > 30 ? 'Suspicious' : 'Clean', score: s, reports: Math.floor(s / 4), country: ['US', 'DE', 'NL', 'IN', 'RU', 'BR'][h % 6] };
}

function risk(sev, prior, ti, host, crit) {
  const why = [`${sev} severity rule +${BASE[sev]}`];
  let s = BASE[sev];
  if (prior) { s += 10; why.push('Repeated activity from this IP +10'); }
  if (ti.verdict === 'Malicious') { s += 30; why.push('Threat intel marks IP malicious +30'); }
  if (crit !== undefined ? crit : CRIT_ASSET.test(host || '')) { s += 10; why.push(`Critical asset (${host}) +10`); }
  return { score: Math.min(100, s), why };
}

// Returns [[ruleId, evidenceLogs], ...] for the newest log. db.logs must already contain it.
function detect(db, log, on) {
  const out = [], m = log.message || '', t = log.ts;
  const win = (type, ms) => db.logs.filter((l) => l.type === type && l.src_ip === log.src_ip && t - l.ts <= ms);
  if (on.brute_force && log.type === 'failed_login') { const w = win('failed_login', 300000); if (w.length >= 5) out.push(['brute_force', w]); }
  if (on.port_scan && log.type === 'port_contact') { const w = win('port_contact', 30000); if (w.length >= 6) out.push(['port_scan', w]); }
  if (on.powershell && /EncodedCommand|DownloadString|Invoke-WebRequest/i.test(m)) out.push(['powershell', [log]]);
  if (on.priv_esc && /added to.*Administrators/i.test(m)) out.push(['priv_esc', [log]]);
  if (on.malware && log.type === 'av_detect') out.push(['malware', [log]]);
  if (on.web_attack && /union\s+select|<script|\.\.\/\.\.\/|or 1=1/i.test(m)) out.push(['web_attack', [log]]);
  return out;
}

function sim(type, t = Date.now()) {
  const ip = Math.random() < 0.35 ? pick([...BAD]) : `${pick(['203.0.113', '198.51.100', '192.0.2'])}.${1 + Math.floor(Math.random() * 250)}`;
  const host = type === 'brute_force' ? 'Auth Server' : pick(HOSTS);
  const L = (i, o) => ({ ts: t + i * 1000, src_ip: ip, host, source: 'simulator', ...o });
  switch (type) {
    case 'brute_force': return Array.from({ length: 6 }, (_, i) => L(i, { type: 'failed_login', message: `Failed login for admin from ${ip}` }));
    case 'port_scan': return [22, 80, 443, 3389, 445, 8080, 3306].map((p, i) => L(i, { type: 'port_contact', message: `Connection attempt to port ${p} from ${ip}` }));
    case 'powershell': return [L(0, { type: 'process', message: 'powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A' })];
    case 'priv_esc': return [L(0, { type: 'group_add', message: 'User jdoe added to Administrators group' })];
    case 'malware': return [L(0, { type: 'av_detect', message: `AV signature match: Trojan.Generic.KD on ${host}` })];
    case 'web_attack': return [L(0, { type: 'web', message: 'GET /products?id=1 UNION SELECT username,password FROM users' })];
    default: return [];
  }
}

module.exports = { REC, RULES, intel, risk, detect, sim };

// Routine background traffic. Clearly simulated (source: 'simulator'); never matches a detection rule.
const AMB = [['dns', 'Info', 'DNS query resolved'], ['auth', 'Info', 'User login successful'], ['firewall', 'Low', 'Firewall dropped inbound connection'], ['proxy', 'Info', 'HTTPS request allowed'], ['syslog', 'Info', 'Scheduled backup completed'], ['auth', 'Low', 'Password expiry reminder sent']];
function ambient() {
  const a = pick(AMB);
  return { ts: Date.now(), src_ip: '10.0.3.' + (1 + Math.floor(Math.random() * 60)), host: pick(HOSTS), source: 'simulator', type: a[0], sev: a[1], message: a[2] };
}
module.exports.ambient = ambient;
