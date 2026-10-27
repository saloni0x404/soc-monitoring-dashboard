require('dotenv').config();
const path = require('path');
const fs = require('fs');
const http = require('http');
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const E = require('./engine');

const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DIR, 'db.json');
fs.mkdirSync(DIR, { recursive: true });

// ---- tiny JSON "database" (persisted to data/db.json) ----
let db = { users: [], logs: [], alerts: [], rules: {}, incidents: [], assets: [], audit: [], seq: 1 };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch (e) { /* first run */ }
let timer, lastIngest = Date.now();
const save = () => { clearTimeout(timer); timer = setTimeout(() => { db.logs = db.logs.slice(-5000); fs.writeFile(FILE, JSON.stringify(db), () => {}); }, 500); };
const enabled = () => Object.fromEntries(E.RULES.map((r) => [r.id, db.rules[r.id] !== false]));

const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false })); // inline script + Google Fonts; tighten with nonces for production
app.use(express.json());

const sess = session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: 'auto', maxAge: 8 * 3600e3 },
});
app.use(sess);
const auth = (req, res, next) => (req.session.user ? next() : res.status(401).json({ error: 'Login required' }));
const can = (...roles) => (req, res, next) => (roles.includes(req.session.user.role) ? next() : res.status(403).json({ error: 'Your role does not allow this action.' }));
const audit = (req, action, detail = '') => { const u = req && req.session && req.session.user; db.audit.push({ ts: Date.now(), user: u ? u.username : 'system', action, detail: String(detail) }); db.audit = db.audit.slice(-1000); save(); };

// ---- ingest: store logs, run detection, create alerts, broadcast ----
function ingest(batch, quiet) {
  lastIngest = Date.now();
  const created = [];
  for (const l of batch) {
    l.id = db.seq++; db.logs.push(l);
    const host = db.assets.find((x) => x.name === l.host);
    l.sev = l.sev || 'Info'; l.dst = l.dst || (host ? host.ip : '10.0.2.10');
    for (const [rid, ev] of E.detect(db, l, enabled())) {
      const r = E.RULES.find((x) => x.id === rid);
      if (db.alerts.some((a) => a.rule === rid && a.ip === l.src_ip && Math.abs(l.ts - a.ts) < 300000)) continue;
      const prior = db.alerts.some((a) => a.rule === rid && a.ip === l.src_ip);
      const as = db.assets.find((x) => x.name === l.host), ti = E.intel(l.src_ip), k = E.risk(r.sev, prior, ti, l.host, as ? as.criticality === 'Critical' : undefined);
      const a = { id: db.seq++, rule: rid, title: r.title, sev: r.sev, mitre: r.mitre, ip: l.src_ip, host: l.host, risk: k.score, why: k.why, intel: ti, rec: E.REC[rid], evidence: ev.slice(-8).map((e) => e.message), status: 'Open', ack: false, tl: [{ ts: l.ts, text: `Detected by rule: ${r.title}` }], ts: l.ts };
      db.alerts.push(a); created.push(a); ev.forEach((e) => { e.sev = r.sev; });
    }
  }
  save();
  created.forEach((a) => io.emit('alert', a));
  batch.forEach((l) => io.emit('event', l));
  if (batch.length && !quiet) io.emit('stats');
  return created;
}

// ---- auth ----
const fails = {};
app.post('/login', async (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const f = fails[username] || { n: 0, until: 0 };
  if (f.until > Date.now()) return res.status(429).json({ error: 'Account locked for 10 minutes after too many failed attempts.' });
  const u = db.users.find((x) => x.username === username);
  if (!u || !(await bcrypt.compare(String(password), u.password))) {
    f.n++; if (f.n >= 5) { f.until = Date.now() + 600000; f.n = 0; }
    fails[username] = f;
    audit({ session: { user: { username: String(username).slice(0, 30) } } }, 'login_failed', 'Wrong credentials');
    return res.status(401).json({ error: 'Wrong username or password.' });
  }
  delete fails[username]; audit({ session: { user: u } }, 'login', 'Signed in');
  req.session.user = { username: u.username, name: u.name, role: u.role };
  res.json({ ok: true });
});
app.post('/logout', (req, res) => { audit(req, 'logout'); req.session.destroy(() => res.json({ ok: true })); });
app.get('/api/me', auth, (req, res) => res.json(req.session.user));

// ---- API ----
app.get('/api/stats', auth, (req, res) => {
  const rng = { '15m': 900e3, '1h': 3600e3, '24h': 86400e3, '7d': 604800e3 }[req.query.range] || 86400e3, t = Date.now(), H = 3600e3, A = db.alerts.filter((a) => t - a.ts <= rng), open = db.alerts.filter((a) => a.status === 'Open');
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  A.forEach((a) => counts[a.sev]++);
  const bucket = (arr, n, w) => { const o = Array(n).fill(0); arr.forEach((x) => { const i = n - 1 - Math.floor((t - x.ts) / w); if (i >= 0 && i < n) o[i]++; }); return o; };
  const w = { Critical: 40, High: 25, Medium: 10, Low: 3 };
  res.json({
    counts, total: A.length, lastIngest, uptime: Math.round(process.uptime()), simulated: true, incOpen: db.incidents.filter((i) => i.status !== 'Resolved').length, events: db.logs.filter((l) => t - l.ts <= rng).length, openCount: open.length,
    timeline: bucket(db.logs, 10, rng / 10), heat: bucket(db.logs, 24, rng / 24), week: bucket(db.alerts, 6, 24 * H),
    score: Math.max(0, 1000 - open.reduce((s, a) => s + w[a.sev], 0)),
    health: Math.max(0, 100 - open.length * 0.4).toFixed(1),
    byRule: E.RULES.map((r) => [r.short, A.filter((a) => a.rule === r.id).length]),
  });
});
app.get('/api/alerts', auth, (req, res) => res.json(db.alerts.slice().sort((a, b) => b.ts - a.ts).slice(0, 300)));
app.post('/api/alerts/:id/status', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const a = db.alerts.find((x) => x.id === +req.params.id);
  if (!a || !['Open', 'Resolved'].includes(req.body.status)) return res.status(400).json({ error: 'Bad request' });
  a.status = req.body.status; (a.tl = a.tl || []).push({ ts: Date.now(), text: `Marked ${a.status} by ${req.session.user.username}` }); audit(req, 'alert_' + a.status.toLowerCase(), `${a.title} #${a.id}`); save(); io.emit('stats'); res.json(a);
});
app.get('/api/rules', auth, (req, res) => res.json(E.RULES.map((r) => ({ ...r, enabled: enabled()[r.id] }))));
app.post('/api/rules/:id/toggle', auth, (req, res) => {
  if (req.session.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admins only' });
  if (!E.RULES.some((r) => r.id === req.params.id)) return res.status(404).json({ error: 'No such rule' });
  db.rules[req.params.id] = !enabled()[req.params.id]; save(); res.json({ ok: true });
});
app.post('/api/simulate/:type', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const batch = E.sim(req.params.type);
  if (!batch.length) return res.status(400).json({ error: 'Unknown attack type' });
  audit(req, 'simulate', req.params.type);
  res.json({ created: ingest(batch).length });
});
app.get('/api/intel/:ip', auth, (req, res) => {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(req.params.ip)) return res.status(400).json({ error: 'Enter a valid IPv4 address.' });
  res.json(E.intel(req.params.ip));
});
app.get('/api/export.csv', auth, (req, res) => {
  const q = (v) => `"${String(v).replace(/"/g, '""')}"`;
  const rows = db.alerts.map((a) => [new Date(a.ts).toISOString(), a.title, a.sev, a.mitre, a.host, a.ip, a.risk, a.status].map(q).join(','));
  res.type('text/csv').attachment('alerts.csv').send(['Time,Rule,Severity,MITRE,Host,IP,Risk,Status', ...rows].join('\n'));
});
app.post('/api/reset', auth, (req, res) => {
  if (req.session.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admins only' });
  db.logs = []; db.alerts = []; save(); io.emit('stats'); res.json({ ok: true });
});

// ---- incidents (escalated alerts with owner, status and notes) ----
app.get('/api/team', auth, (req, res) => res.json(db.users.map((u) => u.username)));
app.get('/api/incidents', auth, (req, res) => res.json(db.incidents.slice().sort((a, b) => b.updated - a.updated)));
app.post('/api/incidents', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const a = db.alerts.find((x) => x.id === +(req.body || {}).alertId);
  if (!a) return res.status(400).json({ error: 'Alert not found.' });
  let i = db.incidents.find((x) => x.alertId === a.id);
  if (!i) {
    i = { id: db.seq++, ref: 'INC-' + (1001 + db.incidents.length), alertId: a.id, title: a.title, sev: a.sev, host: a.host, ip: a.ip, status: 'Open', assignee: '', notes: [], created: Date.now(), updated: Date.now() };
    db.incidents.push(i); audit(req, 'incident_created', `${i.ref} from alert #${a.id}`); save(); io.emit('stats');
  }
  res.json(i);
});
app.post('/api/incidents/:id', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const i = db.incidents.find((x) => x.id === +req.params.id), b = req.body || {};
  if (!i) return res.status(404).json({ error: 'Incident not found.' });
  if (['Open', 'Investigating', 'Resolved'].includes(b.status)) { i.status = b.status; audit(req, 'incident_status', `${i.ref} set to ${b.status}`); }
  if (typeof b.assignee === 'string' && (b.assignee === '' || db.users.some((u) => u.username === b.assignee))) { i.assignee = b.assignee; audit(req, 'incident_assigned', `${i.ref} to ${b.assignee || 'nobody'}`); }
  if (b.note && String(b.note).trim()) i.notes.push({ by: req.session.user.username, ts: Date.now(), text: String(b.note).slice(0, 500) });
  i.updated = Date.now(); save(); io.emit('stats'); res.json(i);
});

// ---- assets ----
app.get('/api/assets', auth, (req, res) => {
  const seen = {}; db.logs.forEach((l) => { if (!seen[l.host] || l.ts > seen[l.host]) seen[l.host] = l.ts; });
  res.json(db.assets.map((a) => ({ ...a, seen: seen[a.name] || 0, open: db.alerts.filter((x) => x.host === a.name && x.status === 'Open').length })));
});
app.post('/api/assets', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const { name, ip, type, criticality } = req.body || {};
  if (!name || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip || '') || !['Low', 'Medium', 'High', 'Critical'].includes(criticality)) return res.status(400).json({ error: 'Enter a name, a valid IPv4 address and a criticality.' });
  db.assets.push({ id: db.seq++, name: String(name).slice(0, 40), ip, type: String(type || 'Server').slice(0, 20), criticality, status: 'Online' });
  audit(req, 'asset_added', name); save(); res.json({ ok: true });
});
app.delete('/api/assets/:id', auth, can('ADMIN'), (req, res) => { db.assets = db.assets.filter((a) => a.id !== +req.params.id); audit(req, 'asset_removed', req.params.id); save(); res.json({ ok: true }); });

// ---- users and account ----
app.get('/api/users', auth, can('ADMIN'), (req, res) => res.json(db.users.map((u) => ({ username: u.username, name: u.name, role: u.role }))));
app.post('/api/users', auth, can('ADMIN'), async (req, res) => {
  const { name, username, password, role } = req.body || {};
  if (!name || !/^[a-z0-9_.-]{3,20}$/i.test(username || '') || String(password || '').length < 8 || !['ADMIN', 'ANALYST', 'VIEWER'].includes(role)) return res.status(400).json({ error: 'Enter a name, a username (3-20 letters or numbers), a password of 8+ characters and a role.' });
  if (db.users.some((u) => u.username === username)) return res.status(400).json({ error: 'That username is already taken.' });
  db.users.push({ username, name: String(name).slice(0, 40), role, password: await bcrypt.hash(String(password), 10) });
  audit(req, 'user_created', `${username} (${role})`); save(); res.json({ ok: true });
});
app.delete('/api/users/:u', auth, can('ADMIN'), (req, res) => {
  if (req.params.u === req.session.user.username) return res.status(400).json({ error: 'You cannot remove your own account.' });
  db.users = db.users.filter((u) => u.username !== req.params.u); audit(req, 'user_removed', req.params.u); save(); res.json({ ok: true });
});
app.post('/api/password', auth, async (req, res) => {
  const u = db.users.find((x) => x.username === req.session.user.username), { current = '', next = '' } = req.body || {};
  if (!(await bcrypt.compare(String(current), u.password))) return res.status(400).json({ error: 'Current password is wrong.' });
  if (String(next).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  u.password = await bcrypt.hash(String(next), 10); audit(req, 'password_changed'); save(); res.json({ ok: true });
});

// ---- logs and audit trail ----
app.get('/api/logs', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  res.json(db.logs.filter((l) => !q || `${l.message} ${l.host} ${l.src_ip} ${l.type}`.toLowerCase().includes(q)).slice(-150).reverse());
});
app.get('/api/audit', auth, can('ADMIN'), (req, res) => res.json(db.audit.slice(-200).reverse()));

app.post('/api/alerts/:id/ack', auth, can('ADMIN', 'ANALYST'), (req, res) => {
  const a = db.alerts.find((x) => x.id === +req.params.id);
  if (!a) return res.status(404).json({ error: 'Alert not found.' });
  a.ack = !a.ack; (a.tl = a.tl || []).push({ ts: Date.now(), text: `${a.ack ? 'Acknowledged' : 'Acknowledgement removed'} by ${req.session.user.username}` });
  audit(req, a.ack ? 'alert_acknowledged' : 'alert_unacknowledged', `${a.title} #${a.id}`); save(); io.emit('stats'); res.json(a);
});

// ---- pages ----
app.get('/', (req, res) => (req.session.user ? res.sendFile(path.join(__dirname, 'public', 'index.html')) : res.redirect('/login.html')));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ---- Socket.IO (session-authenticated) ----
io.engine.use(sess);
io.use((s, next) => (s.request.session && s.request.session.user ? next() : next(new Error('Unauthorized'))));

// ---- bootstrap ----
function seedDemo() {
  const types = ['brute_force', 'port_scan', 'powershell', 'priv_esc', 'malware', 'web_attack', 'brute_force', 'malware'];
  types.forEach((ty, i) => ingest(E.sim(ty, Date.now() - (i + 1) * 2.5 * 3600e3)));
  db.alerts.slice(0, 2).forEach((a) => { a.status = 'Resolved'; });
  // extra normal traffic so the event charts are not empty
  for (let i = 0; i < 300; i++) db.logs.push({ id: db.seq++, ts: Date.now() - Math.random() * 24 * 3600e3, src_ip: '10.0.0.' + (1 + (i % 50)), host: 'Web Server', source: 'syslog', type: 'info', sev: 'Info', dst: '10.0.2.10', message: 'Routine event' });
  save();
}
(function start() {
  if (!db.users.length) {
    const username = process.env.ADMIN_USERNAME || 'admin';
    db.users.push({ username, name: 'Administrator', role: 'ADMIN', password: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10) });
    console.log(`Admin account created: ${username}`);
  }
  if (!db.assets.length) {
    [['Server-01', '10.0.1.10', 'Server', 'Critical'], ['Auth Server', '10.0.1.20', 'Server', 'Critical'], ['Domain Controller', '10.0.1.5', 'Server', 'Critical'], ['Web Server', '10.0.2.10', 'Server', 'High'], ['Endpoint-247', '10.0.3.47', 'Endpoint', 'Medium'], ['Endpoint-112', '10.0.3.12', 'Endpoint', 'Medium']]
      .forEach(([name, ip, type, criticality]) => db.assets.push({ id: db.seq++, name, ip, type, criticality, status: 'Online' }));
  }
  if (!db.alerts.length) seedDemo();
  const first = db.alerts.find((x) => x.status === 'Open');
  if (!db.incidents.length && first) db.incidents.push({ id: db.seq++, ref: 'INC-1001', alertId: first.id, title: first.title, sev: first.sev, host: first.host, ip: first.ip, status: 'Investigating', assignee: 'admin', notes: [{ by: 'admin', ts: Date.now(), text: 'Escalated for review. Checking source IP reputation.' }], created: Date.now(), updated: Date.now() });
  server.listen(PORT, () => console.log(`SOC Dashboard running at http://localhost:${PORT}`));
  // Background traffic is SIMULATED and labelled as such in the UI. Set AMBIENT=off to disable.
  if (process.env.AMBIENT !== 'off') setInterval(() => ingest([E.ambient()], true), 2500);
})();
