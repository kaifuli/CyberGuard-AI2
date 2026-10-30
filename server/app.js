import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { analyzeUrl } from './url-analysis.js';
import { parseEml } from './eml-parser.js';
import { scenarios, scoreTraining } from './training.js';
import { makePdf, makeUrlPdf, reportObject, urlReportObject } from './report.js';
import { reviewWithCloud } from './cloud-review.js';

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
const cloudAiEnabled = process.env.ENABLE_CLOUD_AI === 'true' && Boolean(process.env.OPENAI_API_KEY);
const configuredDb = process.env.SQLITE_PATH || 'data/cyberguard.sqlite3';
const defaultDbPath = path.isAbsolute(configuredDb) ? configuredDb : path.resolve(ROOT, configuredDb);

const checked = [
  'Urgency, threats, and time pressure',
  'Credential or account verification requests',
  'Sender domain spoofing and brand lookalikes',
  'Unverified links and deceptive URL patterns',
  'Common social engineering language',
  'Requests for sensitive information and one-time codes',
  'Unusual payment and invoice language',
  'Sender and destination-domain consistency',
  'Attachment metadata warnings when available',
  'Supplied email authentication evidence (not independently verified)',
];

export function analyzeEmail(email) {
  const text = `${email.subject}\n${email.body}\n${email.rawHeaders || ''}`.normalize('NFKC').toLowerCase();
  const sender = email.sender.toLowerCase();
  const findings = [];
  const add = (id, title, severity, evidence, why, points) => findings.push({ id, ruleId:id, title, severity, evidence, why, explanation:why, points, nextAction:'Verify the request through a trusted channel before replying, clicking, or sharing information.' });

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

  const secrets = ['one-time code','authentication code','verification code','security code','social security number','routing number','card number','date of birth'];
  const secret = secrets.find(term => text.includes(term));
  if (secret) add('sensitive-data', 'Sensitive information requested', 'High', `The message refers to “${secret}”.`, 'Unexpected requests for authentication codes or sensitive details need independent verification.', 25);

  const payment = ['wire transfer','bank transfer','gift card','invoice overdue','change bank details','new account number','payment today','urgent payment'];
  const paymentHit = payment.find(term => text.includes(term));
  if (paymentHit) add('payment-request', 'Unusual payment or invoice request', 'High', `Payment-related wording detected: “${paymentHit}”.`, 'Payment changes and urgent transfers should be verified using a known contact method.', 22);

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

  const displayedMismatch = [...email.body.matchAll(/([^\n]{1,200}?)\s*(?:->|\|)\s*((?:https?:\/\/|www\.)[^\s<>"']+)/gi)].some(match=>{
    const label=match[1].trim();
    if(!/(?:https?:\/\/|www\.|[\w-]+\.[a-z]{2,})/i.test(label))return false;
    try { const shown=new URL(label.startsWith('http')?label:`https://${label.replace(/^www\./i,'')}`).hostname; const destination=new URL(match[2].replace(/^www\./i,'https://www.')).hostname; return shown.toLowerCase()!==destination.toLowerCase(); } catch { return true; }
  });
  if(displayedMismatch)add('link-text-mismatch','Displayed link differs from destination','High','The displayed link text and extracted destination hostname do not match.','A misleading label can conceal the actual destination. Do not open the link; verify through a trusted channel.',25);

  const senderDomain = sender.split('@')[1] || '';
  const mismatched = urls.some(raw => { try { const host = new URL(raw.replace(/^hxxps?:/i,'https:')).hostname.toLowerCase(); return host && senderDomain && !host.endsWith(senderDomain) && !host.endsWith('.example.test'); } catch { return false; } });
  if (mismatched) add('identity-link-mismatch', 'Sender and link domains differ', 'Medium', `A message link uses a hostname different from sender domain “${senderDomain}”.`, 'Different domains may be legitimate, but unexpected sign-in or payment destinations deserve verification.', 12);

  if (Array.isArray(email.attachments) && email.attachments.length) add('attachment-metadata', 'Attachment requires context check', 'Medium', `Attachment metadata lists ${email.attachments.length} file(s): ${email.attachments.slice(0,3).map(x=>x.name||'unnamed file').join(', ')}.`, 'Unexpected files can carry risk. This application never opens or executes attachments.', 12);
  const auth = String(email.rawHeaders || '').match(/(?:spf|dkim|dmarc)=[a-z]+/ig) || [];
  if (auth.some(x=>/=(?:fail|softfail|none|neutral)/i.test(x))) add('auth-evidence', 'Authentication failure evidence present', 'High', auth.filter(x=>/=(?:fail|softfail|none|neutral)/i.test(x)).join(', '), 'This text comes from supplied headers and is not independently authenticated by this local tool.', 18);

  const manipulationTerms = ['click here', 'act now', 'avoid interruption', 'keep this confidential', 'payment overdue', 'gift card'];
  const manipulation = manipulationTerms.filter(term => text.includes(term));
  if (manipulation.length) add('social', 'Social engineering language', 'Medium',
    `Common pressure phrase detected: “${manipulation[0]}”.`,
    'This wording can encourage a rushed response or discourage independent checks.', 12);

  const groupPoints = new Map();
  for (const finding of findings) groupPoints.set(finding.id, Math.max(groupPoints.get(finding.id)||0, finding.points));
  const score = Math.min(100, [...groupPoints.values()].reduce((total, points) => total + points, 0));
  const risk = score >= 85 ? 'Critical' : score >= 65 ? 'High' : score >= 30 ? 'Medium' : 'Low';
  const labels = { Critical: 'Strong Warning Signs', High: 'Potential Phishing', Medium: 'Needs Review', Low: 'No Strong Warning Signs' };
  const summaries = {
    Critical: 'Multiple strong warning signs are present. Treat this message as untrusted and verify through a separate, trusted channel.',
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
    score INTEGER NOT NULL, risk TEXT NOT NULL CHECK(risk IN ('Critical','High','Medium','Low')),
    label TEXT NOT NULL, summary TEXT NOT NULL, findings_json TEXT NOT NULL,
    checked_json TEXT NOT NULL, created_at TEXT NOT NULL,
    feedback TEXT CHECK(feedback IS NULL OR feedback IN ('Helpful','Not Helpful')),
    feedback_text TEXT NOT NULL DEFAULT ''
  )`);
  const schema = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='analyses'").get()?.sql || '';
  if (!schema.includes("'Critical'")) db.exec(`ALTER TABLE analyses RENAME TO analyses_legacy;
    CREATE TABLE analyses (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
      score INTEGER NOT NULL, risk TEXT NOT NULL CHECK(risk IN ('Critical','High','Medium','Low')), label TEXT NOT NULL,
      summary TEXT NOT NULL, findings_json TEXT NOT NULL, checked_json TEXT NOT NULL, created_at TEXT NOT NULL,
      feedback TEXT CHECK(feedback IS NULL OR feedback IN ('Helpful','Not Helpful')), feedback_text TEXT NOT NULL DEFAULT '');
    INSERT INTO analyses SELECT * FROM analyses_legacy;
    DROP TABLE analyses_legacy;`);
  const columns = new Set(db.prepare('PRAGMA table_info(analyses)').all().map(column => column.name));
  if (!columns.has('metadata_json')) db.exec("ALTER TABLE analyses ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'");
  db.exec("UPDATE analyses SET risk='Critical', label='Strong Warning Signs' WHERE score>=85 AND risk<>'Critical'");
  db.exec("UPDATE analyses SET risk='High', label='Potential Phishing' WHERE score BETWEEN 65 AND 84 AND risk<>'High'");
  db.exec(`CREATE TABLE IF NOT EXISTS url_analyses (id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER, original TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS training_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, difficulty TEXT NOT NULL, answers_json TEXT NOT NULL, score_json TEXT NOT NULL, created_at TEXT NOT NULL);`);
  return db;
}

function rowToAnalysis(row) {
  const metadata = row.metadata_json ? JSON.parse(row.metadata_json) : {};
  const { cloudReview, ...emailMetadata } = metadata;
  return {
    id: row.id,
    email: { sender: row.sender, subject: row.subject, body: row.body, ...emailMetadata },
    score: row.score, risk: row.risk, label: row.label, summary: row.summary,
    findings: JSON.parse(row.findings_json), checked: JSON.parse(row.checked_json),
    createdAt: row.created_at, feedback: row.feedback, feedbackText: row.feedback_text,
    ...(cloudReview ? { cloudReview } : {}),
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

export function createServer({ dbPath = defaultDbPath, cloudEnabled = cloudAiEnabled, cloudReviewer = reviewWithCloud } = {}) {
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
        send(res, 200, { status: 'ok', database: 'sqlite', cloudAI: cloudEnabled });
      } else if (req.method === 'GET' && url.pathname === '/api/history') {
        const rows = db.prepare('SELECT * FROM analyses ORDER BY id DESC').all();
        send(res, 200, { items: rows.map(rowToAnalysis) });
      } else if (req.method === 'POST' && url.pathname === '/api/analyze') {
        const data = await readJson(req);
        const email = { sender: data.sender, subject: data.subject, body: data.body, recipient: data.recipient || '', rawHeaders: data.rawHeaders || '', attachments: Array.isArray(data.attachments) ? data.attachments : [] };
        if (![email.sender, email.subject, email.body].every(value => typeof value === 'string' && value.trim())) {
          send(res, 400, { error: 'Sender, subject, and message body are required' }); return;
        }
        if (typeof email.recipient!=='string'||email.recipient.length>320||typeof email.rawHeaders!=='string'||email.rawHeaders.length>32_000||!Array.isArray(email.attachments)||email.attachments.length>100||email.attachments.some(x=>!x||typeof x.name!=='string'||x.name.length>255||(x.contentType!==undefined&&typeof x.contentType!=='string'))) {
          send(res,400,{error:'Optional recipient, headers, or attachment metadata is malformed or exceeds its size limit.'});return;
        }
        if (email.sender.length > 320 || email.subject.length > 998 || email.body.length > 50_000) {
          send(res, 400, { error: 'Email fields exceed the allowed size' }); return;
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.sender.trim())) {
          send(res, 400, { error: 'Enter a sender address in a valid email format' }); return;
        }
        email.sender = email.sender.trim(); email.subject = email.subject.trim();
        const result = analyzeEmail(email);
        let cloudReview = null;
        let cloudError = null;
        if (data.useCloudAI === true) {
          if (!cloudEnabled) {
            send(res, 503, { error: 'Cloud AI is not enabled or configured. Set ENABLE_CLOUD_AI=true and OPENAI_API_KEY in .env, then restart the API.' }); return;
          }
          try { cloudReview = await cloudReviewer(email); }
          catch (error) { cloudError = error instanceof Error ? error.message : 'Cloud AI review failed'; }
        }
        const inserted = db.prepare(`INSERT INTO analyses
          (sender,subject,body,score,risk,label,summary,findings_json,checked_json,created_at,metadata_json)
          VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(email.sender, email.subject, email.body, result.score,
          result.risk, result.label, result.summary, JSON.stringify(result.findings), JSON.stringify(result.checked), result.createdAt, JSON.stringify({recipient:email.recipient,rawHeaders:email.rawHeaders,attachments:email.attachments, ...(cloudReview ? {cloudReview} : {})}));
        const foundUrls = [...new Set((email.body.match(/(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"']+/gi) || []).map(x=>x.replace(/[),.;]+$/,'')))];
        for (const foundUrl of foundUrls) { const urlResult=analyzeUrl(foundUrl); db.prepare('INSERT INTO url_analyses(analysis_id,original,result_json,created_at) VALUES(?,?,?,?)').run(Number(inserted.lastInsertRowid),foundUrl,JSON.stringify(urlResult),result.createdAt); }
        send(res, 201, { ...rowToAnalysis(db.prepare('SELECT * FROM analyses WHERE id=?').get(inserted.lastInsertRowid)), cloudError });
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
        db.prepare('DELETE FROM url_analyses WHERE analysis_id=?').run(id);
        const deleted = db.prepare('DELETE FROM analyses WHERE id=?').run(id);
        if (!deleted.changes) send(res, 404, { error: 'Analysis not found' });
        else send(res, 200, { deleted: true });
      } else if (req.method === 'GET' && url.pathname === '/api/dashboard') {
        const rows = db.prepare('SELECT * FROM analyses ORDER BY id DESC').all();
        const today = new Date().toISOString().slice(0, 10);
        const distribution = { Critical: 0, High: 0, Medium: 0, Low: 0 }, activity = {}, indicators = {};
        for (const row of rows) {
          distribution[row.risk] = (distribution[row.risk] || 0) + 1;
          const day = row.created_at.slice(0, 10); activity[day] = (activity[day] || 0) + 1;
          for (const item of JSON.parse(row.findings_json)) indicators[item.title] = (indicators[item.title] || 0) + 1;
        }
        const suspicious = rows.filter(x => x.risk !== 'Low').length;
        send(res, 200, { total:rows.length, suspicious, highCritical:rows.filter(x => ['High','Critical'].includes(x.risk)).length,
          detectionRate:rows.length ? Math.round(suspicious/rows.length*100) : 0, analyzedToday:rows.filter(x=>x.created_at.startsWith(today)).length,
          distribution, activity:Object.entries(activity).sort(([a],[b])=>a.localeCompare(b)).slice(-14), indicators:Object.entries(indicators).sort((a,b)=>b[1]-a[1]).slice(0,8), recent:rows.slice(0,10).map(rowToAnalysis) });
      } else if (req.method === 'POST' && url.pathname === '/api/url/analyze') {
        const data = await readJson(req);
        if (!Array.isArray(data.urls) || data.urls.length > 50) { send(res,400,{error:'Provide up to 50 URLs.'}); return; }
        if (data.urls.some(item => typeof item!=='string' && (!item || typeof item.url!=='string' || (item.displayedText!==undefined && typeof item.displayedText!=='string')))) { send(res,400,{error:'Each URL must be a string or an object with a URL string.'}); return; }
        const createdAt = new Date().toISOString();
        const items = data.urls.map(item => { const input=typeof item==='string'?{url:item}:item; const result=analyzeUrl(input.url,input.displayedText||'');
          const inserted=db.prepare('INSERT INTO url_analyses(analysis_id,original,result_json,created_at) VALUES(?,?,?,?)').run(data.analysisId||null,result.original,JSON.stringify(result),createdAt);
          return {...result,id:Number(inserted.lastInsertRowid),analysisId:data.analysisId||null,createdAt}; });
        send(res,201,{items});
      } else if (req.method === 'GET' && url.pathname === '/api/url/history') {
        send(res,200,{items:db.prepare('SELECT id,analysis_id AS analysisId,original,result_json AS result,created_at AS createdAt FROM url_analyses ORDER BY id DESC LIMIT 100').all().map(x=>({...x,result:JSON.parse(x.result)}))});
      } else if (req.method === 'GET' && /^\/api\/url\/reports\/\d+\.(json|pdf)$/.test(url.pathname)) {
        const [,id,format]=url.pathname.match(/^\/api\/url\/reports\/(\d+)\.(json|pdf)$/),row=db.prepare('SELECT * FROM url_analyses WHERE id=?').get(Number(id));
        if(!row){send(res,404,{error:'URL report not found'});return;}
        const item={id:Number(id),result:JSON.parse(row.result_json)};
        if(format==='json'){const payload=JSON.stringify(urlReportObject(item),null,2);res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Disposition':`attachment; filename="cyberguard-url-report-${id}.json"`,'Cache-Control':'no-store'});res.end(payload);}
        else {const pdf=makeUrlPdf(item);res.writeHead(200,{'Content-Type':'application/pdf','Content-Disposition':`attachment; filename="cyberguard-url-report-${id}.pdf"`,'Content-Length':pdf.length,'Cache-Control':'no-store'});res.end(pdf);}
      } else if (req.method === 'POST' && url.pathname === '/api/eml/parse') {
        const data=await readJson(req); try { send(res,200,parseEml(data.content)); } catch(error) { send(res,400,{error:error.message}); }
      } else if (req.method === 'GET' && url.pathname === '/api/training/scenarios') {
        send(res,200,{items:scenarios.map(({id,difficulty,sender,subject,body,expected,explanation})=>({id,difficulty,sender,subject,body,expected,explanation}))});
      } else if (req.method === 'POST' && url.pathname === '/api/analyze/preview') {
        const data=await readJson(req);
        if (![data.sender,data.subject,data.body].every(x=>typeof x==='string')){send(res,400,{error:'Sender, subject, and body are required.'});return;}
        send(res,200,analyzeEmail({sender:data.sender,subject:data.subject,body:data.body}));
      } else if (req.method === 'POST' && url.pathname === '/api/training/sessions') {
        const data=await readJson(req);
        if (!Array.isArray(data.answers)||data.answers.length>scenarios.length||!['Beginner','Intermediate','Advanced','All'].includes(data.difficulty)) { send(res,400,{error:'Invalid training session.'}); return; }
        const valid=data.answers.map(a=>{const s=scenarios.find(x=>x.id===a?.id);if(!s||typeof a.answer!=='string'||!['Safe','Suspicious','Phishing'].includes(a.answer))throw Object.assign(new Error('Invalid training answer.'),{status:400});return{id:a.id,answer:a.answer,expected:s.expected,correct:a.answer===s.expected};});
        const score=scoreTraining(valid),createdAt=new Date().toISOString(),inserted=db.prepare('INSERT INTO training_sessions(difficulty,answers_json,score_json,created_at) VALUES(?,?,?,?)').run(data.difficulty,JSON.stringify(valid),JSON.stringify(score),createdAt);
        send(res,201,{id:Number(inserted.lastInsertRowid),difficulty:data.difficulty,answers:valid,score,createdAt});
      } else if (req.method === 'GET' && url.pathname === '/api/training/stats') {
        const rows=db.prepare('SELECT score_json FROM training_sessions').all().map(x=>JSON.parse(x.score_json)),total=rows.reduce((n,x)=>n+x.total,0),correct=rows.reduce((n,x)=>n+x.correct,0);
        send(res,200,{sessions:rows.length,accuracy:total?Math.round(correct/total*100):0,answered:total});
      } else if (req.method === 'GET' && /^\/api\/reports\/\d+\.(json|pdf)$/.test(url.pathname)) {
        const [,id,format]=url.pathname.match(/^\/api\/reports\/(\d+)\.(json|pdf)$/);
        const row=db.prepare('SELECT * FROM analyses WHERE id=?').get(Number(id));
        if(!row){send(res,404,{error:'Analysis not found'});return;}
        const analysis=rowToAnalysis(row), urls=db.prepare('SELECT result_json FROM url_analyses WHERE analysis_id=?').all(Number(id)).map(x=>JSON.parse(x.result_json));
        if(format==='json'){const payload=JSON.stringify(reportObject(analysis,urls),null,2);res.writeHead(200,{'Content-Type':'application/json; charset=utf-8','Content-Disposition':`attachment; filename="cyberguard-report-${id}.json"`,'Cache-Control':'no-store'});res.end(payload);}
        else {const pdf=makePdf(analysis,urls);res.writeHead(200,{'Content-Type':'application/pdf','Content-Disposition':`attachment; filename="cyberguard-report-${id}.pdf"`,'Content-Length':pdf.length,'Cache-Control':'no-store'});res.end(pdf);}
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
