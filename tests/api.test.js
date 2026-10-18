import test, { after, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeEmail, createServer } from '../server/app.js';

const sample = {
  sender: 'security-alert@micros0ft-support.example.test',
  subject: 'URGENT: Your account will be suspended today',
  body: 'We detected unusual activity on your account. Your account may be suspended within 30 minutes. Verify your account immediately using the link below.\n\nhxxp://login-microsoft.example.test/verify',
};

test('sample email produces a high score and explainable findings', () => {
  const result = analyzeEmail(sample);
  assert.equal(result.score, 100);
  assert.equal(result.risk, 'High');
  assert.equal(result.findings.length, 4);
  assert.ok(result.findings.some(f => f.title === 'Possible brand impersonation'));
});

test('ordinary benign email produces low risk and no findings', () => {
  const result = analyzeEmail({ sender: 'alex@northwind.com', subject: 'Team lunch', body: 'Shall we meet next Thursday? Please reply with your preference.' });
  assert.equal(result.score, 0);
  assert.equal(result.risk, 'Low');
  assert.equal(result.findings.length, 0);
});

test('medium classification derives from matched weights', () => {
  const result = analyzeEmail({ sender: 'it@contoso.com', subject: 'Please sign in', body: 'Open https://portal.contoso.com/info to continue.' });
  assert.equal(result.score, 35);
  assert.equal(result.risk, 'Medium');
});

describe('local HTTP API with temporary SQLite database', () => {
  let server; let base; let temp;
  before(async () => {
    temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cyberguard-test-'));
    server = createServer({ dbPath: path.join(temp, 'test.sqlite3') });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(async () => {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(temp, { recursive: true, force: true });
  });
  async function call(endpoint, method = 'GET', body) {
    const response = await fetch(`${base}${endpoint}`, { method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined });
    return { status: response.status, data: await response.json() };
  }
  test('health check responds with SQLite status', async () => {
    assert.deepEqual((await call('/api/health')).data, { status: 'ok', database: 'sqlite' });
  });
  test('analyze persists, history lists, feedback updates, delete removes', async () => {
    const created = await call('/api/analyze', 'POST', sample);
    assert.equal(created.status, 201);
    const id = created.data.id;
    assert.equal((await call('/api/history')).data.items[0].id, id);
    const feedback = await call(`/api/feedback/${id}`, 'POST', { feedback: 'Helpful', feedbackText: 'Clear explanation' });
    assert.equal(feedback.data.feedback, 'Helpful');
    assert.equal(feedback.data.feedbackText, 'Clear explanation');
    assert.deepEqual((await call(`/api/history/${id}`, 'DELETE')).data, { deleted: true });
    assert.deepEqual((await call('/api/history')).data.items, []);
  });
  test('invalid email returns a handled 400 response', async () => {
    const result = await call('/api/analyze', 'POST', { ...sample, sender: 'bad' });
    assert.equal(result.status, 400);
    assert.match(result.data.error, /valid email/);
  });
});
