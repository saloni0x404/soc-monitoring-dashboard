/**
 * logParser.js
 *
 * Takes a raw event object (from the simulator now, from real log
 * ingestion sources in a future version) and normalizes it into the
 * shape the Log model expects, filling in sane defaults for anything
 * missing. This is the single place that "cleans up" incoming events
 * before they're saved - keeps the rest of the app from worrying about
 * inconsistent field names/casing/missing values.
 *
 * In Step 3, parsed logs get handed to the detectionEngine right after
 * this step.
 */

const VALID_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function parseEvent(rawEvent) {
  const severity = VALID_SEVERITIES.includes((rawEvent.severity || '').toUpperCase())
    ? rawEvent.severity.toUpperCase()
    : 'INFO';

  return {
    timestamp: rawEvent.timestamp || new Date(),
    source: rawEvent.source || 'Unknown',
    event_type: rawEvent.event_type || 'GENERIC_EVENT',
    severity,
    username: rawEvent.username || null,
    source_ip: rawEvent.source_ip || null,
    destination_ip: rawEvent.destination_ip || null,
    hostname: rawEvent.hostname || null,
    message: rawEvent.message || 'No message provided',
    raw_log: rawEvent.raw_log || JSON.stringify(rawEvent),
  };
}

/**
 * Parses and saves a single event via the Log model.
 * Accepts a Sequelize model reference so this stays framework-light
 * and easily testable.
 */
async function parseAndSave(Log, rawEvent) {
  const parsed = parseEvent(rawEvent);
  return Log.create(parsed);
}

/**
 * Batch version - used by the simulator when a single button click
 * needs to generate multiple related events (e.g. 5 failed logins).
 */
async function parseAndSaveBatch(Log, rawEvents) {
  const parsedEvents = rawEvents.map(parseEvent);
  return Log.bulkCreate(parsedEvents);
}

module.exports = { parseEvent, parseAndSave, parseAndSaveBatch };
