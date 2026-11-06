/**
 * Integration tests (supertest): real Express app, real SQLite file in the
 * OS temp dir. Covers auth, CSRF, CSP header, role checks, log import and
 * user management.
 */
const os = require('os');
const path = require('path');
const fs = require('fs');

process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-secret';
process.env.DB_PATH = path.join(os.tmpdir(), `soc-test-${process.pid}.sqlite`);
delete process.env.ABUSEIPDB_API_KEY;

const request = require('supertest');
const bcrypt = require('bcrypt');
const { app } = require('../app');
const { sequelize, User, Rule, Alert, Log } = require('../models');
const { loadRuleDefs } = require('../services/ruleDefs');

const PASSWORD = 'CorrectHorse-99';
const AUTH_SAMPLE = fs.readFileSync(path.join(__dirname, '..', 'public', 'samples', 'sample-auth.log'), 'utf8');

const tokenFrom = (html) => (html.match(/name="csrf-token" content="([a-f0-9]+)"/) || [])[1];

async function loginAs(username) {
  const agent = request.agent(app);
  const page = await agent.get('/login');
  const res = await agent.post('/login').type('form').send({ username, password: PASSWORD, _csrf: tokenFrom(page.text) });
  expect(res.status).toBe(302);
  const home = await agent.get('/simulator');
  return { agent, token: tokenFrom(home.text) };
}

let admin;
let viewer;

beforeAll(async () => {
  await sequelize.sync({ force: true });
  const password = await bcrypt.hash(PASSWORD, 4);
  await User.create({ name: 'Admin', username: 'admin', password, role: 'ADMIN' });
  await User.create({ name: 'View', username: 'viewer', password, role: 'VIEWER' });
  for (const d of Object.values(loadRuleDefs())) {
    await Rule.create({ name: d.name, title: d.title, description: d.description, severity: d.severity, rule_type: d.rule_type, mitre_id: d.mitre_id });
  }
  admin = await loginAs('admin');
  viewer = await loginAs('viewer');
});

afterAll(async () => {
  await sequelize.close();
  try { fs.unlinkSync(process.env.DB_PATH); } catch (e) { /* ignore */ }
});

describe('public surface', () => {
  test('protected pages redirect to login', async () => {
    const res = await request(app).get('/alerts');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('CSP header is strict and has no unsafe-inline scripts', async () => {
    const res = await request(app).get('/login');
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("script-src 'self' https://cdn.jsdelivr.net");
    expect(csp).toContain("object-src 'none'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
  });

  test('favicon is served', async () => {
    expect((await request(app).get('/favicon.svg')).status).toBe(200);
  });
});

describe('CSRF', () => {
  test('login POST without token is rejected', async () => {
    const res = await request(app).post('/login').type('form').send({ username: 'admin', password: PASSWORD });
    expect(res.status).toBe(403);
  });

  test('state-changing JSON request without token is rejected', async () => {
    const res = await admin.agent.post('/ingest').send({ content: AUTH_SAMPLE });
    expect(res.status).toBe(403);
  });
});

describe('log import', () => {
  test('imports an auth.log and the detection engine raises alerts', async () => {
    const res = await admin.agent.post('/ingest').set('X-CSRF-Token', admin.token)
      .send({ format: 'auto', content: AUTH_SAMPLE, filename: 'sample-auth.log' });
    expect(res.status).toBe(200);
    expect(res.body.imported).toBeGreaterThan(10);
    expect(res.body.alertsCreated).toBeGreaterThan(0);
    expect(await Log.count()).toBe(res.body.imported);
    const names = (await Alert.findAll()).map((a) => a.rule_name);
    expect(names).toContain('brute-force');
    expect(names).toContain('password-spraying');
  });

  test('garbage input is rejected cleanly', async () => {
    const res = await admin.agent.post('/ingest').set('X-CSRF-Token', admin.token).send({ content: 'hello world' });
    expect(res.status).toBe(400);
  });

  test('viewer role cannot import', async () => {
    const res = await viewer.agent.post('/ingest').set('X-CSRF-Token', viewer.token).send({ content: AUTH_SAMPLE });
    expect(res.status).toBe(403);
  });

  test('demo seed creates data', async () => {
    const res = await admin.agent.post('/simulator/demo-seed').set('X-CSRF-Token', admin.token);
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });
});

describe('user management', () => {
  test('viewer cannot open /users', async () => {
    expect((await viewer.agent.get('/users')).status).toBe(403);
  });

  test('admin can create a user; weak password rejected', async () => {
    const weak = await admin.agent.post('/users').type('form')
      .send({ _csrf: admin.token, name: 'New', username: 'newbie', password: 'short', role: 'ANALYST' });
    expect(weak.text).toContain('at least 10');

    const ok = await admin.agent.post('/users').type('form')
      .send({ _csrf: admin.token, name: 'New', username: 'newbie', password: 'LongEnough-123', role: 'ANALYST' });
    expect(ok.text).toContain('created');
    expect(await User.findOne({ where: { username: 'newbie' } })).toBeTruthy();
  });

  test('admin cannot disable own account', async () => {
    const me = await User.findOne({ where: { username: 'admin' } });
    const res = await admin.agent.post(`/users/${me.id}/toggle`).type('form').send({ _csrf: admin.token });
    expect(res.text).toContain('cannot disable your own');
  });
});
