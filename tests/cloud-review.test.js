import test from 'node:test';
import assert from 'node:assert/strict';
import { reviewWithCloud } from '../server/cloud-review.js';

test('cloud review sends only to the configured provider and extracts advisory text', async () => {
  let sent;
  const result = await reviewWithCloud({ sender: 'person@example.test', subject: 'Hello', body: 'Please meet at 2.', rawHeaders: '' }, {
    apiKey: 'test-key', model: 'test-model',
    fetchImpl: async (url, options) => {
      sent = { url, options, body: JSON.parse(options.body) };
      return { ok: true, json: async () => ({ output_text: 'No strong indicators; verify unexpected requests.' }) };
    },
  });
  assert.equal(sent.url, 'https://api.openai.com/v1/responses');
  assert.equal(sent.options.headers.Authorization, 'Bearer test-key');
  assert.equal(sent.body.store, false);
  assert.match(sent.body.input, /person@example\.test/);
  assert.equal(result.provider, 'OpenAI');
  assert.equal(result.model, 'test-model');
  assert.match(result.text, /verify unexpected requests/);
});

test('cloud review refuses to run without a server-side key', async () => {
  await assert.rejects(() => reviewWithCloud({ sender: 'a@b.test', subject: 's', body: 'b' }, { apiKey: '' }), /not configured/);
});
