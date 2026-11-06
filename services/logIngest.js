/**
 * logIngest.js
 *
 * Turns REAL log text into the same raw-event shape the simulator produces,
 * so uploaded logs flow through the exact same parser -> detection engine ->
 * risk score -> alert pipeline.
 *
 * Supported formats:
 *   auth    Linux /var/log/auth.log or /var/log/secure (sshd / sudo lines)
 *   access  Apache / Nginx access log (common or combined format)
 *   csv     CSV with a header row (timestamp,source,event_type,severity,
 *           username,source_ip,destination_ip,hostname,message,country)
 *
 * Everything here is pure (text in, events out) - no DB, no network.
 */

const MAX_EVENTS = 2000;
const MAX_LINE = 2000;

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

// ---------- timestamps ----------

function parseSyslogTimestamp(str, now = new Date()) {
  if (/^\d{4}-\d{2}-\d{2}T/.test(str)) {
    const d = new Date(str);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  const m = str.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
  if (!m || !(m[1] in MONTHS)) return null;
  const build = (year) => new Date(Date.UTC(year, MONTHS[m[1]], +m[2], +m[3], +m[4], +m[5]));
  let d = build(now.getUTCFullYear());
  // syslog has no year: a "future" date means it was last year (e.g. Dec log read in Jan)
  if (d.getTime() > now.getTime() + 86400000) d = build(now.getUTCFullYear() - 1);
  return d;
}

function parseAccessTimestamp(str) {
  const m = str.match(/^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-])(\d{2})(\d{2}))?/);
  if (!m || !(m[2] in MONTHS)) return null;
  let ms = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]);
  if (m[7]) {
    const offset = (+m[8] * 60 + +m[9]) * 60000;
    ms -= m[7] === '+' ? offset : -offset;
  }
  return new Date(ms);
}

// ---------- auth.log ----------

const SYSLOG_LINE = /^(\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w.\-/]+)(?:\[\d+\])?:\s+(.*)$/;
const SSH_FAILED = /Failed (?:password|publickey|keyboard-interactive\/pam) for (?:invalid user )?(\S+) from (\S+) port \d+/;
const SSH_ACCEPTED = /Accepted (?:password|publickey|keyboard-interactive\/pam|hostbased) for (\S+) from (\S+) port \d+/;

function parseAuthLog(text, now = new Date()) {
  const events = [];
  let skipped = 0;
  const lines = text.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.slice(0, MAX_LINE);
    if (!line.trim()) continue;
    const m = line.match(SYSLOG_LINE);
    if (!m) { skipped++; continue; }

    const [, tsStr, hostname, program, msg] = m;
    const timestamp = parseSyslogTimestamp(tsStr, now);
    if (!timestamp) { skipped++; continue; }

    let ev = null;
    let sm;
    if ((sm = msg.match(SSH_FAILED))) {
      ev = {
        event_type: 'FAILED_LOGIN', severity: 'MEDIUM', username: sm[1], source_ip: sm[2],
        message: `Failed SSH login for user '${sm[1]}' from ${sm[2]}`,
      };
    } else if ((sm = msg.match(SSH_ACCEPTED))) {
      ev = {
        event_type: 'SUCCESSFUL_LOGIN', severity: 'INFO', username: sm[1], source_ip: sm[2],
        message: `Successful SSH login for user '${sm[1]}' from ${sm[2]}`,
      };
    } else if (program === 'sudo' && /NOT in sudoers/.test(msg)) {
      const um = msg.match(/^\s*(\S+)\s*:/);
      ev = {
        event_type: 'PRIVILEGE_ESCALATION', severity: 'HIGH', username: um ? um[1] : null, source_ip: null,
        message: `Unauthorized sudo attempt${um ? ` by '${um[1]}'` : ''} (user not in sudoers)`,
      };
    }

    if (!ev) { skipped++; continue; }
    events.push({ ...ev, timestamp, source: 'Linux', hostname, raw_log: line });
    if (events.length >= MAX_EVENTS) break;
  }
  return { events, skipped, truncated: events.length >= MAX_EVENTS };
}

// ---------- web access log ----------

const ACCESS_LINE = /^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) \S+(?: "[^"]*" "([^"]*)")?/;

function safeDecode(s) {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch (e) { return s; }
}

/** Returns a short label if the request looks malicious, else null. */
function classifyRequest(path, userAgent = '') {
  const decoded = safeDecode(path).toLowerCase();
  if (/(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema|;\s*drop\s+table)/.test(decoded)) return 'SQL injection';
  if (/\.\.[/\\]/.test(decoded) || /etc\/passwd/.test(decoded) || /%2e%2e/i.test(path)) return 'path traversal';
  if (/<script|javascript:|onerror\s*=|onload\s*=/.test(decoded)) return 'cross-site scripting';
  if (/(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra)/i.test(userAgent)) return 'scanner user-agent';
  return null;
}

function parseAccessLog(text) {
  const events = [];
  let skipped = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.slice(0, MAX_LINE);
    if (!line.trim()) continue;
    const m = line.match(ACCESS_LINE);
    if (!m) { skipped++; continue; }

    const [, ip, user, tsStr, method, reqPath, status, ua] = m;
    const timestamp = parseAccessTimestamp(tsStr);
    if (!timestamp) { skipped++; continue; }

    const attack = classifyRequest(reqPath, ua || '');
    let ev = null;
    if (attack) {
      ev = {
        event_type: 'WEB_ATTACK', severity: 'HIGH', username: null,
        message: `Malicious request pattern detected (${attack}): ${method} ${reqPath.slice(0, 200)}`,
      };
    } else if (status === '401') {
      ev = {
        event_type: 'FAILED_LOGIN', severity: 'MEDIUM', username: user !== '-' ? user : null,
        message: `Web authentication failure (HTTP 401) for ${method} ${reqPath.slice(0, 200)}`,
      };
    }
    if (!ev) { skipped++; continue; } // ordinary traffic is not stored

    events.push({ ...ev, timestamp, source: 'Web Server', source_ip: ip, raw_log: line });
    if (events.length >= MAX_EVENTS) break;
  }
  return { events, skipped, truncated: events.length >= MAX_EVENTS };
}

// ---------- CSV ----------

function splitCsvLine(line) {
  const out = [];
  let cur = '';
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQ) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') inQ = false;
      else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out.map((s) => s.trim());
}

function parseCsv(text, now = new Date()) {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) return { events: [], skipped: 0, truncated: false, error: 'CSV needs a header row and at least one data row.' };

  const header = splitCsvLine(lines[0]).map((h) => h.toLowerCase());
  if (!header.includes('message') && !header.includes('event_type')) {
    return { events: [], skipped: 0, truncated: false, error: 'CSV header must include at least "message" or "event_type".' };
  }

  const events = [];
  let skipped = 0;
  for (let i = 1; i < lines.length; i++) {
    const cells = splitCsvLine(lines[i].slice(0, MAX_LINE));
    const row = {};
    header.forEach((h, idx) => { row[h] = cells[idx] || ''; });

    const ts = row.timestamp ? new Date(row.timestamp) : now;
    const eventType = (row.event_type || 'GENERIC_EVENT').toUpperCase().replace(/\s+/g, '_');
    const geo = row.country ? ` geo=${row.country.replace(/\s+/g, '_')}` : '';
    events.push({
      timestamp: Number.isNaN(ts.getTime()) ? now : ts,
      source: row.source || 'CSV Import',
      event_type: eventType,
      severity: row.severity,
      username: row.username || null,
      source_ip: row.source_ip || null,
      destination_ip: row.destination_ip || null,
      hostname: row.hostname || null,
      message: row.message || `${eventType} event`,
      raw_log: `${lines[i].slice(0, 500)}${geo}`,
    });
    if (events.length >= MAX_EVENTS) break;
  }
  return { events, skipped, truncated: events.length >= MAX_EVENTS };
}

// ---------- entry points ----------

function detectFormat(text) {
  const first = text.split(/\r?\n/).find((l) => l.trim());
  if (!first) return null;
  if (ACCESS_LINE.test(first)) return 'access';
  if (SYSLOG_LINE.test(first)) return 'auth';
  const h = first.toLowerCase();
  if (h.includes(',') && (h.includes('event_type') || h.includes('message'))) return 'csv';
  return null;
}

function parseLogText(format, text, now = new Date()) {
  const fmt = !format || format === 'auto' ? detectFormat(text) : format;
  if (!fmt) return { format: null, events: [], skipped: 0, truncated: false, error: 'Could not detect the log format. Pick one manually.' };
  if (fmt === 'auth') return { format: fmt, ...parseAuthLog(text, now) };
  if (fmt === 'access') return { format: fmt, ...parseAccessLog(text) };
  if (fmt === 'csv') return { format: fmt, ...parseCsv(text, now) };
  return { format: fmt, events: [], skipped: 0, truncated: false, error: `Unknown format "${fmt}".` };
}

module.exports = {
  parseLogText, detectFormat, parseAuthLog, parseAccessLog, parseCsv,
  classifyRequest, parseSyslogTimestamp, parseAccessTimestamp, MAX_EVENTS,
};
