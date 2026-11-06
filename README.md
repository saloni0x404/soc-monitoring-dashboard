# AI-Powered SOC Monitoring Dashboard

**A lightweight, real-time Security Operations Center (SOC) monitoring platform for security log analysis, threat detection, and incident monitoring.**

Built with Node.js, Express.js, SQLite, EJS, and Socket.IO, this project processes security logs, detects suspicious activities using a rule-based detection engine, maps findings to MITRE ATT&CK, and provides explainable risk scoring with threat intelligence enrichment.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Technology Stack](#technology-stack)
- [System Architecture](#system-architecture)
- [Detection Capabilities](#detection-capabilities)
- [MITRE ATT&CK Integration](#mitre-attck-integration)
- [Security Architecture](#security-architecture)
- [Configuration Reference](#configuration-reference)
- [Project Structure](#project-structure)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Testing](#testing)
- [Deployment](#deployment)
- [Engineering Decisions](#engineering-decisions)
- [Future Enhancements](#future-enhancements)
- [Limitations](#limitations)
- [License](#license)
- [Author](#author)

---

## Overview

The AI-Powered SOC Monitoring Dashboard is a web-based security monitoring application designed to demonstrate core Security Operations Center workflows.

It provides a centralized interface for importing security logs, identifying suspicious activities, generating alerts, evaluating event risk, and monitoring security events in real time.

The platform combines rule-based threat detection, MITRE ATT&CK mapping, IP reputation analysis, and optional AI-assisted security explanations.

The application uses a lightweight, single-process architecture with SQLite for data persistence.

### Project Objectives

- Implement practical SOC monitoring workflows.
- Analyze authentication and web server logs.
- Identify common attack patterns.
- Correlate security events with MITRE ATT&CK.
- Visualize alerts and security incidents.
- Explore threat intelligence integration.
- Implement AI-assisted security analysis.

## Key Features

| Feature | Description |
|---|---|
| Log Ingestion | Import Linux authentication, Apache, Nginx, and CSV logs |
| Threat Detection | Identify suspicious activities using configurable detection rules |
| MITRE ATT&CK | Map detection rules to relevant ATT&CK techniques |
| Risk Scoring | Calculate explainable security risk scores from 0–100 |
| Threat Intelligence | Enrich IP addresses using AbuseIPDB |
| Real-Time Monitoring | Receive live event updates through Socket.IO |
| Alert Management | Review alerts and manage incident workflows |
| Data Visualization | Monitor event activity and severity using Chart.js |
| AI Security Analyst | Optional Gemini, OpenAI, and Ollama integration |
| Administration | Manage users, roles, and audit records |
| Reporting | Export security reports in CSV and JSON formats |

## Technology Stack

| Component | Technology |
|---|---|
| Runtime | Node.js |
| Backend | Express.js |
| Frontend | EJS, HTML, CSS, JavaScript |
| UI Framework | Bootstrap |
| Database | SQLite |
| ORM | Sequelize |
| Real-Time Communication | Socket.IO |
| Visualization | Chart.js |
| Authentication | bcrypt, Express sessions |
| Security | Helmet, CSRF protection, rate limiting |
| Threat Intelligence | AbuseIPDB |
| AI Integration | Gemini, OpenAI, Ollama |
| Testing | Jest, Supertest |
| Deployment | Docker, Render |

## System Architecture

The application follows a centralized event-processing architecture.

```text
                 SECURITY ANALYST
                        |
                        v
               Web-Based Dashboard
                 EJS / Bootstrap
                        |
                        v
                  Express Server
                        |
              +---------+---------+
              |                   |
          Log Upload           Simulator
              |                   |
              +---------+---------+
                        |
                        v
                    Log Parser
                        |
                        v
                 Event Processing
                        |
                        v
                 Detection Engine
                        |
              +---------+---------+
              |                   |
          Risk Engine        Threat Intel
              |                   |
              +---------+---------+
                        |
                        v
                 SQLite Database
                        |
                        v
                 Socket.IO Events
                        |
                        v
                Live Dashboard UI
```

Every incoming event passes through the centralized processing pipeline in `services/pipeline.js`.

Detection thresholds are maintained in JSON configuration files under `rules/`.

## Detection Capabilities

The detection engine currently supports 10 categories of suspicious activity.

| No. | Detection | Purpose |
|---:|---|---|
| 1 | Brute Force | Detect repeated authentication failures |
| 2 | Password Spraying | Identify login attempts targeting multiple accounts |
| 3 | Port Scanning | Identify suspicious scanning activity |
| 4 | Impossible Travel | Identify unusual login location patterns |
| 5 | Off-Hours Login | Flag authentication outside expected hours |
| 6 | Web Attacks | Detect SQL injection, XSS, path traversal, and scanners |
| 7 | Suspicious PowerShell | Identify suspicious PowerShell activity |
| 8 | Privilege Escalation | Flag suspicious privilege-related events |
| 9 | Malware Indicators | Identify events matching configured malware indicators |
| 10 | IP Volume Anomaly | Identify statistically unusual IP activity |

## MITRE ATT&CK Integration

Detection rules are mapped to relevant techniques from the MITRE ATT&CK framework.

Examples include:

| Technique ID | Technique Name |
|---|---|
| T1110 | Brute Force |
| T1110.003 | Password Spraying |
| T1078 | Valid Accounts |
| T1190 | Exploit Public-Facing Application |
| T1595 | Active Scanning |

This integration provides additional context for understanding detected security activities.

## Security Architecture

Security controls implemented in the application include:

- Password hashing using bcrypt with cost factor 12.
- Account lockout after five failed login attempts for 15 minutes.
- Forced password change on first login.
- Session-bound CSRF protection.
- Helmet security headers.
- Strict Content Security Policy.
- HTTP-only, SameSite, and Secure cookie settings.
- Role-based access control (ADMIN, ANALYST, VIEWER).
- Login rate limiting.
- Authenticated Socket.IO sessions.
- Environment-based secret management.
- Git-ignored `.env` and SQLite database files.

**Known limitation:** Existing sessions belonging to disabled users remain valid until session expiration (up to eight hours).

## Configuration Reference

The application uses environment variables to manage authentication, security settings, integrations, and database configuration.

| Variable | Purpose |
|---|---|
| `SESSION_SECRET` | Secure session signing |
| `ADMIN_USERNAME` | Initial administrator username |
| `ADMIN_PASSWORD` | Initial administrator password |
| `DEMO_MODE` | Enable demonstration mode |
| `ABUSEIPDB_API_KEY` | Optional IP reputation integration |
| `AI_PROVIDER` | Configure the selected AI provider |
| `CSP_REPORT_ONLY` | Configure Content Security Policy reporting mode |
| `DB_PATH` | Configure the SQLite database location |

### Security Recommendations

- Use strong and unique credentials.
- Generate a secure session secret.
- Store API keys in environment variables.
- Never commit `.env` files.
- Do not expose credentials in screenshots or logs.

Refer to `.env.example` for the available environment configuration.

## Project Structure

```text
soc-monitoring-dashboard/
│
├── app.js
│
├── routes/
│
├── services/
│   ├── logIngest
│   ├── pipeline
│   ├── detectionEngine
│   ├── riskEngine
│   ├── threatIntel
│   ├── mitre
│   └── aiService
│
├── rules/
│
├── middleware/
│
├── models/
│
├── views/
│
├── public/
│   └── samples/
│
├── tests/
│
├── site/
│
├── .env.example
├── docker-compose.yml
├── render.yaml
├── package.json
└── README.md
```

## Installation and Setup

### Prerequisites

- Node.js
- npm
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/saloni0x404/soc-monitoring-dashboard.git

cd soc-monitoring-dashboard
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

For Windows:

```bash
copy .env.example .env
```

For Linux/macOS:

```bash
cp .env.example .env
```

Configure the required variables in `.env`:

```env
SESSION_SECRET=your_strong_random_secret
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_strong_admin_password
```

Never commit `.env` or expose application credentials.

### 4. Start the Application

```bash
npm start
```

Access the dashboard:

```text
http://localhost:3000
```

Log in using the configured administrator credentials. You will be required to change the password on your first login.

## Usage

After starting the application:

1. Log in using the configured administrator credentials.
2. Change the initial administrator password.
3. Navigate to **Import Logs**.
4. Import a sample authentication log.
5. Review detected events and generated alerts.
6. Explore the live monitoring dashboard.
7. Investigate event severity and risk scores.
8. Explore incident management and reporting.
9. Configure optional threat intelligence and AI integrations.

A simulator is also available for demonstration purposes. Simulated events are synthetic; log imports can be used to analyze real log files.

## Testing

The project uses Jest and Supertest for unit and integration testing.

Run the test suite:

```bash
npm test
```

## Deployment

### Docker

Configure `.env` and execute:

```bash
docker compose up -d --build
```

The application uses a persistent Docker volume named `soc-data`.

### Render

The repository includes a `render.yaml` configuration for deployment through Render Blueprints.

Deployment steps:

1. Push the project to GitHub.
2. Open Render.
3. Select **New + → Blueprint**.
4. Connect the repository.
5. Configure the required administrator password.
6. Deploy the application.

**Note:** SQLite persistence requires a persistent disk. Without persistent storage, database data may reset during redeployment.

Optional AbuseIPDB integration:

```env
ABUSEIPDB_API_KEY=your_api_key
```

## Engineering Decisions

**Single-Process Architecture**

Express and SQLite keep the application lightweight and straightforward to deploy.

**Event-Time-Based Detection**

Historical events are evaluated using their original timestamps rather than the server's current time.

**Statistical Anomaly Detection**

IP activity is compared against other IP activity to identify unusual volume patterns.

**Explainable Risk Scoring**

Security events receive risk scores based on severity, repeated activity, and threat intelligence.

**AI Safety**

The AI analyst is restricted to a predefined read-only function allow-list rather than executing AI-generated SQL.

**Alert Deduplication**

One open alert per rule and IP combination helps reduce repeated alerts.

## Future Enhancements

- Syslog and endpoint-agent ingestion.
- Custom detection rule management.
- Immediate session revocation.
- PostgreSQL support for multi-instance deployments.
- Additional threat intelligence integrations.
- Advanced anomaly detection.
- Enhanced incident investigation workflows.

## Limitations

- The application currently uses SQLite rather than a distributed database.
- The detection engine relies on configured rules and thresholds.
- AbuseIPDB enrichment requires an optional API key for external lookups.
- AI-assisted analysis requires an optional provider configuration.
- Disabled-user sessions are not immediately revoked.
- The included simulator generates synthetic demonstration events.

## License

This project is licensed under the MIT License.

## Author

**Saloni Ghodechor**

Computer Engineering Student | Cybersecurity

Areas of Interest:

- Security Operations Center (SOC)
- Threat Detection and Analysis
- Digital Forensics
- Incident Response
- Defensive Security

GitHub: [@saloni0x404](https://github.com/saloni0x404)

---

<p align="center">

**AI-Powered SOC Monitoring Dashboard**

*Building practical skills in security monitoring, threat detection, and incident analysis.*

</p>
