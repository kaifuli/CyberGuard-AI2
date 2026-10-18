import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadEnv() {
  const envFile = path.join(ROOT, '.env');
  if (!fs.existsSync(envFile)) return;
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][\w]*)\s*=\s*(.*?)\s*$/);
    if (match && !match[1].startsWith('#')) process.env[match[1]] ??= match[2].replace(/^['"]|['"]$/g, '');
  }
}
loadEnv();
const configuredHost = process.env.API_HOST || '127.0.0.1';
if (configuredHost !== '127.0.0.1') throw new Error('API_HOST must remain 127.0.0.1 for local-only operation.');
const port = Number(process.env.API_PORT || 8000);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('API_PORT must be from 1 to 65535.');
const frontendPort = Number(process.env.VITE_PORT || 5173);
const allowedOrigin = `http://127.0.0.1:${frontendPort}`;
const configuredDb = process.env.SQLITE_PATH || 'data/cyberguard.sqlite3';
const defaultDbPath = path.isAbsolute(configuredDb) ? configuredDb : path.resolve(ROOT, configuredDb);

const checked = [
  'Urgency, threats, and time pressure',
  'Credential or account verification requests',
  'Sender domain spoofing and brand lookalikes',
  'Unverified links and deceptive URL patterns',
  'Common social engineering language',
];

export function analyzeEmail(email) {
  const text = `${email.subject}\n${email.body}`.toLowerCase();
  const sender = email.sender.toLowerCase();
  const findings = [];
  const add = (id, title, severity, evidence, why, points) => findings.push({ id, title, severity, evidence, why, points });

  const urgencyTerms = ['urgent', 'immediately', 'within', 'today', 'suspended', 'suspend', 'expires', 'minutes', 'act now', 'final warning', 'unusual activity'];
  const urgency = urgencyTerms.filter(term => text.includes(term));
  if (urgency.length) add('urgency', 'Urgency and time pressure', 'High',
    `Time-pressure language detected: “${urgency.slice(0, 3).join('”, “')}”.`,
    'Threats and short deadlines can pressure people into skipping normal verification.', 25);

  const credentialTerms = ['verify your account', 'verify account', 'enter your password', 'credentials', 'sign in', 'log in', 'confirm your account', 'account verification'];
  const credentials = credentialTerms.filter(term => text.includes(term));
  if (credentials.length) add('credentials', 'Account verification request', 'High',
    `The message asks the recipient to ${credentials[0]}.`,
    'Unexpected requests to verify an account may lead to credential theft.', 25);

  const brands = ['microsoft', 'micros0ft', 'apple', 'google', 'amazon', 'paypal', 'netflix', 'bank'];
  const brand = brands.find(name => sender.includes(name) && ['support', 'security', 'alert', '0'].some(cue => sender.includes(cue)));
  const domain = sender.split('@')[1] || '';
  if (brand && (sender.includes('0') || ['example', 'test', '-'].some(cue => domain.includes(cue)))) {
    add('sender', 'Possible brand impersonation', 'High',
      `The sender combines “${brand}” with a support or security cue, and uses the domain “${domain || 'unknown'}”.`,
      'A familiar brand name in an address does not prove the sender is affiliated with that organization.', 25);
  } else if (domain && (domain.includes('example') || domain.includes('test'))) {
    add('sender-domain', 'Unverified sender domain', 'Medium',
      `The sender domain “${domain}” is a reserved demonstration domain.`,
      'The sender cannot be authenticated from the address text alone.', 12);
  }

  const urls = email.body.match(/(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"']+/gi) || [];
  const suspicious = urls.filter(url => /hxxp|example|test|login|verify|secure|account|\d{1,3}(?:\.\d{1,3}){3}/i.test(url));
  if (suspicious.length) add('link', 'Unverified verification link', 'High',
    `A link with a login or verification cue was found: ${suspicious[0]}`,
    'The link destination is unverified. Do not open it; inspect links only through approved security tools.', 25);
  else if (urls.length) add('link', 'Link present in message', 'Medium',
    `${urls.length} link${urls.length === 1 ? '' : 's'} found in the message body.`,
    'Links deserve care, especially when a message unexpectedly asks you to sign in.', 10);

  const manipulationTerms = ['click here', 'act now', 'avoid interruption', 'keep this confidential', 'payment overdue', 'gift card'];
  const manipulation = manipulationTerms.filter(term => text.includes(term));
  if (manipulation.length) add('social', 'Social engineering language', 'Medium',
    `Common pressure phrase detected: “${manipulation[0]}”.`,
    'This wording can encourage a rushed response or discourage independent checks.', 12);

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.points, 0));
  const risk = score >= 65 ? 'High' : score >= 30 ? 'Medium' : 'Low';
  const labels = { High: 'Potential Phishing', Medium: 'Needs Review', Low: 'No Strong Warning Signs' };
  const summaries = {
    High: 'Several warning signs are present. Treat the message as untrusted and verify through a separate, trusted channel.',
    Medium: 'Some signals deserve a closer look. Check the sender and context before responding or following any links.',
    Low: 'The local rules found few common warning signs. This does not prove the message is safe.',
  };
  return { email, score, risk, label: labels[risk], summary: summaries[risk], findings, checked,
    createdAt: new Date().toISOString() };
}

function createDatabase(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
    score INTEGER NOT NULL, risk TEXT NOT NULL CHECK(risk IN ('High','Medium','Low')),
    label TEXT NOT NULL, summary TEXT NOT NULL, findings_json TEXT NOT NULL,
    checked_json TEXT NOT NULL, created_at TEXT NOT NULL,
    feedback TEXT CHECK(feedback IS NULL OR feedback IN ('Helpful','Not Helpful')),
    feedback_text TEXT NOT NULL DEFAULT ''
  )`);
  return db;
}

function rowToAnalysis(row) {
  return {
    id: row.id,
    email: { sender: row.sender, subject: row.subject, body: row.body },
    score: row.score, risk: row.risk, label: row.label, summary: row.summary,
    findings: JSON.parse(row.findings_json), checked: JSON.parse(row.checked_json),
    createdAt: row.created_at, feedback: row.feedback, feedbackText: row.feedback_text,
  };
}

async function readJson(req) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 1_000_000) throw Object.assign(new Error('Request body exceeds 1 MB'), { status: 413 });
  }
  try {
    const data = JSON.parse(body);
    if (!data || Array.isArray(data) || typeof data !== 'object') throw new Error();
    return data;
  } catch {
    throw Object.assign(new Error('Request body must be a JSON object'), { status: 400 });
  }
}

function send(res, status, data) {
  const payload = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload), 'Cache-Control': 'no-store' });
  res.end(payload);
}

export function createServer({ dbPath = defaultDbPath } = {}) {
  const db = createDatabase(dbPath);
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    try {
      const origin = req.headers.origin;
      if (origin && origin !== allowedOrigin) { send(res, 403, { error: 'Origin is not allowed by the local API' }); return; }
      if (origin) {
        res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      }
      if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
      if (req.method === 'GET' && url.pathname === '/api/health') {
        db.prepare('SELECT 1').get();
        send(res, 200, { status: 'ok', database: 'sqlite' });
      } else if (req.method === 'GET' && url.pathname === '/api/history') {
        const rows = db.prepare('SELECT * FROM analyses ORDER BY id DESC').all();
        send(res, 200, { items: rows.map(rowToAnalysis) });
      } else if (req.method === 'POST' && url.pathname === '/api/analyze') {
        const data = await readJson(req);
        const email = { sender: data.sender, subject: data.subject, body: data.body };
        if (![email.sender, email.subject, email.body].every(value => typeof value === 'string' && value.trim())) {
          send(res, 400, { error: 'Sender, subject, and message body are required' }); return;
        }
        if (email.sender.length > 320 || email.subject.length > 998 || email.body.length > 50_000) {
          send(res, 400, { error: 'Email fields exceed the allowed size' }); return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.sender.trim())) {
          send(res, 400, { error: 'Enter a sender address in a valid email format' }); return;
        }
        email.sender = email.sender.trim(); email.subject = email.subject.trim();
        const result = analyzeEmail(email);
        const inserted = db.prepare(`INSERT INTO analyses
          (sender,subject,body,score,risk,label,summary,findings_json,checked_json,created_at)
          VALUES (?,?,?,?,?,?,?,?,?,?)`).run(email.sender, email.subject, email.body, result.score,
          result.risk, result.label, result.summary, JSON.stringify(result.findings), JSON.stringify(result.checked), result.createdAt);
        send(res, 201, rowToAnalysis(db.prepare('SELECT * FROM analyses WHERE id=?').get(inserted.lastInsertRowid)));
      } else if (req.method === 'POST' && /^\/api\/feedback\/\d+$/.test(url.pathname)) {
        const data = await readJson(req);
        if (!['Helpful', 'Not Helpful'].includes(data.feedback) || typeof (data.feedbackText ?? '') !== 'string' || (data.feedbackText ?? '').length > 2000) {
          send(res, 400, { error: 'Feedback must be Helpful or Not Helpful; note limit is 2,000 characters' }); return;
        }
        const id = Number(url.pathname.split('/').at(-1));
        const updated = db.prepare('UPDATE analyses SET feedback=?,feedback_text=? WHERE id=?').run(data.feedback, data.feedbackText ?? '', id);
        const row = db.prepare('SELECT * FROM analyses WHERE id=?').get(id);
        if (!updated.changes) send(res, 404, { error: 'Analysis not found' });
        else send(res, 200, rowToAnalysis(row));
      } else if (req.method === 'DELETE' && /^\/api\/history\/\d+$/.test(url.pathname)) {
        const id = Number(url.pathname.split('/').at(-1));
        const deleted = db.prepare('DELETE FROM analyses WHERE id=?').run(id);
        if (!deleted.changes) send(res, 404, { error: 'Analysis not found' });
        else send(res, 200, { deleted: true });
      } else {
        send(res, 404, { error: 'Endpoint not found' });
      }
    } catch (error) {
      if (res.headersSent) { res.destroy(); return; }
      const status = error.status || 500;
      if (status === 500) console.error(`Local API error: ${error.message}`);
      send(res, status, { error: status === 500 ? 'Local service request failed' : error.message });
    }
  });
  server.on('close', () => db.close());
  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = createServer();
  server.listen(port, '127.0.0.1', () => console.log(`CyberGuard API listening on http://127.0.0.1:${port} (SQLite: ${defaultDbPath})`));
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
