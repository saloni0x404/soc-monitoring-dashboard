/**
 * simulator.js
 *
 * Generates completely synthetic, fake security events for demo purposes.
 * Nothing here touches a real system, sends real network traffic, or
 * executes anything - it only builds plain JS objects that look like
 * what a real event would look like, so the rest of the dashboard
 * (log parser -> later: detection engine -> alerts) has something
 * realistic to work with.
 */

const SOURCES = ['Windows', 'Linux', 'Firewall', 'Web Server'];
const USERNAMES = ['admin', 'jsmith', 'root', 'administrator', 'svc_backup', 'guest'];
const HOSTNAMES = ['WEB-SRV-01', 'DC-01', 'FILE-SRV-02', 'WKSTN-014', 'DB-SRV-01'];

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomIp() {
  // Biased toward a small pool of "attacker" IPs so brute force /
  // port scan patterns look realistic (same IP repeating)
  const attackerPool = ['203.0.113.45', '198.51.100.23', '45.33.32.156', '185.220.101.7'];
  return Math.random() < 0.7 ? randomItem(attackerPool) : `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function randomInternalIp() {
  return `192.168.1.${Math.floor(Math.random() * 254) + 1}`;
}

function offsetSeconds(baseDate, seconds) {
  return new Date(baseDate.getTime() + seconds * 1000);
}

// ---- Individual event-type generators ----
// Each returns an array of raw event objects ready for the log parser.

function generateBruteForce() {
  const ip = randomIp();
  const username = randomItem(USERNAMES);
  const hostname = randomItem(HOSTNAMES);
  const base = new Date();
  const events = [];
  const attempts = 5 + Math.floor(Math.random() * 3); // 5-7 attempts

  for (let i = 0; i < attempts; i++) {
    events.push({
      timestamp: offsetSeconds(base, i * 2),
      source: 'Windows',
      event_type: 'FAILED_LOGIN',
      severity: 'MEDIUM',
      username,
      source_ip: ip,
      hostname,
      message: `Failed login attempt for user '${username}' from ${ip}`,
      raw_log: `[${offsetSeconds(base, i * 2).toISOString()}] AUTH FAILURE user=${username} src=${ip} host=${hostname}`,
    });
  }
  return events;
}

function generatePortScan() {
  const ip = randomIp();
  const hostname = randomItem(HOSTNAMES);
  const base = new Date();
  const ports = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389, 8080, 8443];
  const events = [];

  ports.forEach((port, i) => {
    events.push({
      timestamp: offsetSeconds(base, i),
      source: 'Firewall',
      event_type: 'PORT_SCAN',
      severity: 'MEDIUM',
      source_ip: ip,
      destination_ip: randomInternalIp(),
      hostname,
      message: `Connection attempt to port ${port} from ${ip}`,
      raw_log: `[${offsetSeconds(base, i).toISOString()}] FW DENY src=${ip} dst_port=${port} host=${hostname}`,
    });
  });
  return events;
}

function generateSuspiciousPowerShell() {
  const ip = randomInternalIp();
  const hostname = randomItem(HOSTNAMES);
  const username = randomItem(USERNAMES);
  const keywords = ['-EncodedCommand', 'DownloadString', 'Invoke-WebRequest'];
  const keyword = randomItem(keywords);

  return [{
    timestamp: new Date(),
    source: 'Windows',
    event_type: 'SUSPICIOUS_POWERSHELL',
    severity: 'HIGH',
    username,
    source_ip: ip,
    hostname,
    message: `PowerShell execution with suspicious flag '${keyword}' by ${username}`,
    raw_log: `powershell.exe ${keyword} <base64 payload omitted> user=${username} host=${hostname}`,
  }];
}

function generatePrivilegeEscalation() {
  const ip = randomInternalIp();
  const hostname = randomItem(HOSTNAMES);
  const username = randomItem(USERNAMES);

  return [{
    timestamp: new Date(),
    source: 'Windows',
    event_type: 'PRIVILEGE_ESCALATION',
    severity: 'CRITICAL',
    username,
    source_ip: ip,
    hostname,
    message: `User '${username}' was added to local Administrators group`,
    raw_log: `[Event 4732] Member added to security-enabled local group. Member: ${username} Group: Administrators Host: ${hostname}`,
  }];
}

function generateMalware() {
  const ip = randomInternalIp();
  const hostname = randomItem(HOSTNAMES);
  const fileNames = ['invoice_2024.exe', 'update_flash.exe', 'setup_tool.scr', 'readme.exe'];
  const fileName = randomItem(fileNames);

  return [{
    timestamp: new Date(),
    source: 'Windows',
    event_type: 'MALWARE_DETECTED',
    severity: 'CRITICAL',
    source_ip: ip,
    hostname,
    message: `Malware signature match: ${fileName} quarantined`,
    raw_log: `AV ALERT: Trojan.Generic.${Math.floor(Math.random() * 9000) + 1000} detected in ${fileName} on ${hostname}, action=quarantined`,
  }];
}

function generateSuspiciousLogin() {
  const ip = randomIp();
  const hostname = randomItem(HOSTNAMES);
  const username = randomItem(USERNAMES);
  const countries = ['Russia', 'North Korea', 'Nigeria', 'China'];

  return [{
    timestamp: new Date(),
    source: 'Windows',
    event_type: 'SUSPICIOUS_LOGIN',
    severity: 'HIGH',
    username,
    source_ip: ip,
    hostname,
    message: `Successful login for '${username}' from unusual location (${randomItem(countries)})`,
    raw_log: `AUTH SUCCESS user=${username} src=${ip} host=${hostname} geo=${randomItem(countries)} flag=impossible_travel`,
  }];
}

function generateWebAttack() {
  const ip = randomIp();
  const paths = [
    "/login.php?id=1' OR '1'='1",
    '/search?q=<script>alert(1)</script>',
    '/../../../../etc/passwd',
    '/wp-admin/admin-ajax.php?action=eval',
  ];

  return [{
    timestamp: new Date(),
    source: 'Web Server',
    event_type: 'WEB_ATTACK',
    severity: 'HIGH',
    source_ip: ip,
    message: `Malicious request pattern detected: ${randomItem(paths)}`,
    raw_log: `${ip} - - [${new Date().toISOString()}] "GET ${randomItem(paths)} HTTP/1.1" 403`,
  }];
}

const GENERATORS = {
  'brute-force': generateBruteForce,
  'port-scan': generatePortScan,
  'suspicious-powershell': generateSuspiciousPowerShell,
  'privilege-escalation': generatePrivilegeEscalation,
  'malware': generateMalware,
  'suspicious-login': generateSuspiciousLogin,
  'web-attack': generateWebAttack,
};

function generate(type) {
  const generator = GENERATORS[type];
  if (!generator) {
    throw new Error(`Unknown simulator event type: ${type}`);
  }
  return generator();
}

module.exports = { generate, GENERATORS: Object.keys(GENERATORS) };
