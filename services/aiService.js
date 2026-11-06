/**
 * aiService.js
 *
 * Optional AI layer supporting Gemini, OpenAI, and Ollama.
 * The dashboard works fully with AI disabled (AI_PROVIDER=none or unset).
 *
 * HARD BOUNDARIES (enforced here, not just requested in the prompt):
 * - The AI only ever receives a structured summary object we build ourselves.
 * - The AI only ever returns text. It cannot execute commands, run SQL,
 *   block IPs, delete files, or modify any system state.
 * - The chatbot uses a fixed allow-list of read-only data functions
 *   (getDashboardStats, getCriticalAlerts, etc). AI-generated SQL is never
 *   executed - the AI picks a function NAME from the list, nothing more.
 */

const PROVIDER = (process.env.AI_PROVIDER || 'none').toLowerCase();

function isEnabled() {
  if (PROVIDER === 'none' || !PROVIDER) return false;
  if (PROVIDER === 'gemini') return !!process.env.GEMINI_API_KEY;
  if (PROVIDER === 'openai') return !!process.env.OPENAI_API_KEY;
  if (PROVIDER === 'ollama') return !!process.env.OLLAMA_URL;
  return false;
}

function providerLabel() {
  if (!isEnabled()) return 'Disabled';
  return { gemini: 'Google Gemini', openai: 'OpenAI', ollama: 'Ollama (local)' }[PROVIDER] || PROVIDER;
}

// ---- Provider implementations ----

async function callOllama(prompt) {
  const url = `${(process.env.OLLAMA_URL || 'http://localhost:11434').replace(/\/$/, '')}/api/generate`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: process.env.OLLAMA_MODEL || 'llama3',
      prompt,
      stream: false,
    }),
  });
  if (!res.ok) throw new Error(`Ollama returned ${res.status}`);
  const data = await res.json();
  return data.response;
}

async function callOpenAI(prompt) {
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 800,
    }),
  });
  if (!res.ok) throw new Error(`OpenAI returned ${res.status}`);
  const data = await res.json();
  return data.choices?.[0]?.message?.content || '';
}

async function callGemini(prompt) {
  const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
  });
  if (!res.ok) throw new Error(`Gemini returned ${res.status}`);
  const data = await res.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

async function complete(prompt) {
  if (!isEnabled()) {
    throw new Error('AI is not configured. Set AI_PROVIDER and the matching API key in .env.');
  }
  if (PROVIDER === 'ollama') return callOllama(prompt);
  if (PROVIDER === 'openai') return callOpenAI(prompt);
  if (PROVIDER === 'gemini') return callGemini(prompt);
  throw new Error(`Unknown AI provider: ${PROVIDER}`);
}

// ---- Alert analysis ----

function buildAlertPrompt(alert, relatedLogs, mitre) {
  const evidence = relatedLogs.slice(0, 10).map((l) => `- [${new Date(l.timestamp).toISOString()}] ${l.event_type} from ${l.source_ip || 'n/a'}: ${l.message}`).join('\n');

  return `You are a senior SOC analyst reviewing a security alert. Provide analysis ONLY - do not suggest running commands automatically. A human analyst will decide all actions.

ALERT DATA:
Title: ${alert.title}
Severity: ${alert.severity}
Risk Score: ${alert.risk_score}/100 (${alert.risk_explanation || 'n/a'})
Detection Rule: ${alert.rule_name}
MITRE Technique: ${alert.mitre_id || 'n/a'}${mitre ? ` (${mitre.name} - ${mitre.tactic})` : ''}
Source IP: ${alert.source_ip || 'n/a'}
Username: ${alert.username || 'n/a'}
Hostname: ${alert.hostname || 'n/a'}

EVIDENCE (${relatedLogs.length} related events):
${evidence || 'No related log events.'}

Respond using exactly these headings, in plain text (no markdown symbols):

SUMMARY
WHY THIS IS SUSPICIOUS
EVIDENCE
MITRE TECHNIQUE
RISK ASSESSMENT
RECOMMENDED INVESTIGATION
RECOMMENDED RESPONSE
CONFIDENCE`;
}

async function analyzeAlert(alert, relatedLogs, mitre) {
  const prompt = buildAlertPrompt(alert, relatedLogs, mitre);
  return complete(prompt);
}

// ---- Chatbot with safe, fixed function allow-list ----

const SAFE_FUNCTIONS = [
  'getDashboardStats',
  'getCriticalAlerts',
  'getRecentAlerts',
  'getOpenIncidents',
  'searchLogs',
];

/**
 * Asks the model to pick ONE function name from the allow-list.
 * The model never writes SQL and never receives DB access - we run the
 * chosen function ourselves in routes/ai.js and feed the result back.
 */
async function chooseFunction(question) {
  const prompt = `You are routing a SOC analyst's question to ONE data function.

Available functions (choose exactly one):
${SAFE_FUNCTIONS.map((f) => `- ${f}`).join('\n')}

Question: "${question}"

Reply with ONLY the function name, nothing else. If none fit, reply: none`;

  const raw = (await complete(prompt)).trim();
  const match = SAFE_FUNCTIONS.find((f) => raw.toLowerCase().includes(f.toLowerCase()));
  return match || null;
}

async function answerWithData(question, functionName, data) {
  const prompt = `You are a SOC assistant. Answer the analyst's question using ONLY the data provided. Be concise (2-4 sentences). Do not invent numbers.

Question: "${question}"
Data source: ${functionName}
Data: ${JSON.stringify(data)}

Answer:`;
  return complete(prompt);
}

module.exports = {
  isEnabled,
  providerLabel,
  complete,
  analyzeAlert,
  chooseFunction,
  answerWithData,
  SAFE_FUNCTIONS,
  PROVIDER,
};
