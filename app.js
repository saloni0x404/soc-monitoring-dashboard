require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const morgan = require('morgan');
const bcrypt = require('bcrypt');
const http = require('http');
const { Server } = require('socket.io');

const { sequelize, User, Rule } = require('./models');
const { helmetMiddleware, apiLimiter } = require('./middleware/security');
const { attachUserLocals } = require('./middleware/auth');
const { csrfProtection } = require('./middleware/csrf');
const { loadRuleDefs } = require('./services/ruleDefs');

const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const logsRoutes = require('./routes/logs');
const simulatorRoutes = require('./routes/simulator');
const alertsRoutes = require('./routes/alerts');
const rulesRoutes = require('./routes/rules');
const incidentsRoutes = require('./routes/incidents');
const threatIntelRoutes = require('./routes/threatIntel');
const assetsRoutes = require('./routes/assets');
const aiRoutes = require('./routes/ai');
const reportsRoutes = require('./routes/reports');
const ingestRoutes = require('./routes/ingest');
const usersRoutes = require('./routes/users');

const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Needed so req.ip and secure cookies behave correctly behind a reverse
// proxy (Render, Railway, Fly.io, nginx, etc).
app.set('trust proxy', 1);

// ---- View engine ----
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');
// NOTE: 'layout extractScripts' is intentionally left disabled. It silently
// strips <script src="..."> tags placed in child views. All page scripts are
// loaded from layout.ejs instead.

// ---- Core middleware ----
app.use(helmetMiddleware);
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(express.json({ limit: '2mb' })); // 2mb: uploaded log files are sent as JSON text
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', apiLimiter);

// ---- Session ----
const sessionMiddleware = session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: dbDir }),
  secret: process.env.SESSION_SECRET || 'insecure-dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 8 * 60 * 60 * 1000,
  },
});

app.use(sessionMiddleware);
app.use(attachUserLocals);
app.use(csrfProtection);
app.set('io', io);

// ---- Routes ----
app.use('/', authRoutes);
app.use('/', dashboardRoutes);
app.use('/', logsRoutes);
app.use('/', simulatorRoutes);
app.use('/', alertsRoutes);
app.use('/', rulesRoutes);
app.use('/', incidentsRoutes);
app.use('/', threatIntelRoutes);
app.use('/', assetsRoutes);
app.use('/', aiRoutes);
app.use('/', reportsRoutes);
app.use('/', ingestRoutes);
app.use('/', usersRoutes);

// ---- 404 ----
app.use((req, res) => {
  res.status(404).render('error', {
    title: 'Not Found',
    message: 'The page you are looking for does not exist.',
    user: req.session ? req.session.user : null,
  });
});

// ---- Error handler ----
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', {
    title: 'Server Error',
    message: 'Something went wrong on our end.',
    user: req.session ? req.session.user : null,
  });
});

// ---- Socket.IO (session-authenticated) ----
// Share the Express session with Socket.IO so only logged-in users receive
// live event/alert broadcasts. Without this, anyone able to reach the server
// could subscribe to the live security feed.
io.engine.use(sessionMiddleware);

io.use((socket, next) => {
  const sess = socket.request.session;
  if (sess && sess.user) return next();
  return next(new Error('Unauthorized'));
});

io.on('connection', (socket) => {
  const username = socket.request.session.user.username;
  console.log(`Socket connected: ${username} (${socket.id})`);
  socket.on('disconnect', () => console.log(`Socket disconnected: ${username}`));
});

// ---- Bootstrap ----
async function seedRules() {
  for (const ruleDef of Object.values(loadRuleDefs())) {
    const existing = await Rule.findOne({ where: { name: ruleDef.name } });
    if (!existing) {
      await Rule.create({
        name: ruleDef.name,
        title: ruleDef.title,
        description: ruleDef.description,
        severity: ruleDef.severity,
        enabled: ruleDef.enabled !== false,
        rule_type: ruleDef.rule_type || 'immediate',
        mitre_id: ruleDef.mitre_id,
      });
      console.log(`Seeded detection rule: ${ruleDef.name}`);
    }
  }
}

async function start() {
  try {
    await sequelize.authenticate();
    await sequelize.sync();

    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const existingAdmin = await User.findOne({ where: { username: adminUsername } });
    if (!existingAdmin) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);
      await User.create({
        name: 'Administrator',
        username: adminUsername,
        password: hash,
        role: 'ADMIN',
        mustChangePassword: true,
      });
      console.log(`Default admin account created (username: ${adminUsername}). Password change required on first login.`);
    }

    await seedRules();

    if (process.env.DEMO_MODE === 'true') {
      const { seedDemoData } = require('./services/demoData');
      await seedDemoData({ models: require('./models'), io });
    }

    server.listen(PORT, () => {
      console.log(`SOC Dashboard running at http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start application:', err);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}

module.exports = { app, server, io, start };
