# AI-Powered SOC Dashboard

A lightweight Security Operations Center dashboard in a **single Node.js process**
(Express + SQLite + EJS + Socket.IO). It ingests real log files, detects attacks
with a rule engine mapped to **MITRE ATT&CK**, scores risk, enriches IPs with
**AbuseIPDB**, and shows everything live. No Redis, no Mongo, no microservices.

> A simulator is included for demos. Simulated events are synthetic; the **Import Logs**
> page analyses real `auth.log`, Apache/Nginx access logs and CSV files.

## What it does

| Area | Details |
|------|---------|
| **Log import** | Linux `auth.log`/`secure` (SSH, sudo), Apache/Nginx access logs, CSV. Auto-detect, 2000 events/upload |
| **Detection (10 rules)** | Brute force, password spraying, port scan, impossible travel, off-hours login, web attacks (SQLi / traversal / XSS / scanners), suspicious PowerShell, privilege escalation, malware, **statistical IP-volume anomaly** |
| **MITRE ATT&CK** | Every rule maps to a technique (T1110, T1110.003, T1078, T1190, T1595 ...) |
| **Risk engine** | Explainable 0-100 score: severity + repeated events + threat-intel bonus |
| **Threat intel** | Real AbuseIPDB lookups (cached 1h, 5s timeout) with automatic fallback to a local list |
| **Live UI** | Socket.IO alerts/toasts, Chart.js dashboard, alerts -> incidents workflow, reports (CSV/JSON) |
| **AI analyst** *(optional)* | Gemini / OpenAI / Ollama. AI only writes text; the chatbot can only call a fixed read-only allow-list, never run AI-written SQL |
| **Admin** | User management (roles, disable, password reset), audit log |

## Security design

- bcrypt (cost 12), account lockout (5 fails / 15 min), forced password change on first login, login rate limit
- **CSRF protection** on every state-changing request (session-bound token, constant-time compare)
- **Strict Content-Security-Policy** (no inline scripts, only self + jsDelivr), Helmet headers, `httpOnly`/`sameSite`/`secure` cookies
- Role-based access (ADMIN / ANALYST / VIEWER); Socket.IO requires a logged-in session
- Secrets only in environment variables; `.env` and `*.sqlite` are git-ignored
- Known limitation: a disabled user's *existing* session stays valid until it expires (8h)

## Architecture

```
Browser (EJS + Bootstrap + Chart.js + Socket.IO)
        |
Express (one process)  -- csrf / helmet / session / rate-limit
        |
simulator | log upload  ->  logParser -> pipeline -> detectionEngine -> riskEngine (+ threatIntel)
        |                                                  |
        +---------------- Sequelize ---------------- SQLite (database/soc.sqlite)
```

Every event, from any source, goes through `services/pipeline.js`. Rule thresholds live in `rules/*.json`.
Threshold rules look at windows around each log's own timestamp, so old log files are analysed correctly.

## Run locally

```bash
npm install
cp .env.example .env      # Windows: copy .env.example .env  - then edit it
npm start                 # http://localhost:3000
```

Set `ADMIN_PASSWORD` and `SESSION_SECRET` in `.env` first. Log in as `admin`; you must change the
password at first login. Then try **Import Logs -> sample-auth.log**, or **Live Monitoring -> Load Demo Data**.

```bash
npm test                  # unit + integration tests (Jest, supertest)
```

## Deploy

**Render (recommended)**: push to GitHub -> Render -> *New + -> Blueprint* -> pick the repo (uses `render.yaml`).
Enter `ADMIN_PASSWORD` when asked. `SESSION_SECRET` is generated for you.

- SQLite needs a **persistent disk** (paid instance on Render). On the free plan the app works but data resets
  on each deploy; `DEMO_MODE=true` re-seeds sample data automatically.
- Optional: add `ABUSEIPDB_API_KEY` (free key at abuseipdb.com) for real IP reputation.

**Docker**: `cp .env.example .env`, edit it, then `docker compose up -d --build` (data kept in the `soc-data` volume).

## Environment variables

See `.env.example`. Important: `SESSION_SECRET`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `DEMO_MODE`,
`ABUSEIPDB_API_KEY`, `AI_PROVIDER` (+ key), `CSP_REPORT_ONLY` (debug aid), `DB_PATH`.

## Project layout

```
app.js            server + middleware wiring
routes/           one file per page (ingest, users, alerts, simulator ...)
services/         logIngest, pipeline, detectionEngine, riskEngine, threatIntel, mitre, aiService
rules/*.json      detection rules and their thresholds
middleware/       auth, csrf, security (helmet CSP, rate limits)
models/           Sequelize models (SQLite)
views/ public/    EJS pages, JS, CSS, sample logs (public/samples)
tests/            Jest unit + supertest integration tests
```

## What I learned / design decisions (talking points)

- **Why one process + SQLite?** Simple to deploy and explain; the pipeline is the same shape you would later put behind a queue.
- **Threshold rules anchored to event time**, not wall-clock time, so replaying an old log gives the same alerts.
- **Why a statistical rule?** Fixed thresholds miss "a noisy IP among quiet ones"; comparing an IP to its peers is a tiny, explainable anomaly detector.
- **AI safety:** the model never touches the database. It returns text, or picks a function name from an allow-list.
- **Dedup:** one open alert per rule + IP, so a continuing attack doesn't flood the queue.
- **Next steps:** syslog/agent ingestion, rule editing in the UI, per-user session revocation, Postgres for multi-instance deploys.

## License
MIT

## Marketing site

A static portfolio site is in `site/`. It uses plain HTML, CSS, and browser JavaScript. To preview it locally from the project root, run `node site/serve.js` and open `http://127.0.0.1:4177/site/`. The interactive sample preview reads `public/samples/sample-auth.log` in the browser only. Deploy the `site/` directory as a static site. The `samples/` folder inside `site/` contains the auth.log used by the browser preview.

Creator/contact/GitHub details and the live demo URL are placeholders in the site because those values were not supplied. The dashboard visual is an explicitly labeled empty-data interface preview; the real application screenshots remain to be captured once the project can be run in a suitable local environment.


## Live dashboard UI

The authenticated SOC dashboard uses the existing Socket.IO stream to show connection state and update the event count, latest event feed, alert queue, severity chart, and live toast notifications. The overview charts and panels use the persisted logs and alert data.
