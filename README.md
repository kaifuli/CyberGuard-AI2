# CyberGuard AI — local-first email security workspace

CyberGuard AI is a local Windows application for reviewing email and URL warning signs. The React interface and Node API bind to `127.0.0.1`; records remain in local SQLite. Deterministic scoring always runs locally. An optional OpenAI advisory can be enabled explicitly and is off by default; when selected, sender, subject, message body, and supplied headers are sent from the local backend to OpenAI. No analyzed URLs are opened or fetched.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Node.js 22.13 or newer (Node 24 LTS recommended; includes `node:sqlite`)
- npm (included with Node.js)

No Docker, Python, hosted database, or separately installed database server is required.

## First-time setup

In PowerShell, from this project folder:

```powershell
npm install
Copy-Item .env.example .env
```

`.env` is optional. Defaults: UI `http://127.0.0.1:5173/`, API `http://127.0.0.1:8000`, SQLite `data\cyberguard.sqlite3`. The example contains placeholders only. To enable the optional cloud advisory, set `ENABLE_CLOUD_AI=true` and add your own `OPENAI_API_KEY` to `.env`, then restart the API. Keep `.env` private.

## Start and stop

Start both services, check readiness, and open the browser:

```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1 -OpenBrowser
```

Stop the services started by that script (use the same temporary PowerShell policy option):

```powershell
powershell -ExecutionPolicy Bypass -File .\stop-local.ps1
```

Manual fallback: use two PowerShell windows in this directory. Run `node .\server\app.js` in one and `npm run dev -- --host 127.0.0.1 --strictPort` in the other. Press Ctrl+C in both windows to stop them.

## Features

- **SOC overview:** live KPIs, detection rate (non-Low results / all saved reports; not accuracy), severity distribution, daily activity and risk trends, indicator counts, and searchable/filterable/sortable recent incidents.
- **Email analysis:** local explainable rules for pressure and deadlines, credentials and sensitive data, sender lookalikes, URL patterns, payment requests, supplied authentication failures, sender/link mismatch, and attachment metadata. Risk levels: Low 0–29, Medium 30–64, High 65–84, Critical 85–100. Findings include rule identifiers, evidence, explanation, points, and next action.
- **.eml import:** file picker and drag/drop (up to 1 MB), local parsing, safe text preview, header and attachment metadata. Attachments are never opened or executed. HTML is converted to text before display.
- **URL Analyzer:** inspect multiple pasted URLs using static parsing only. It never resolves, opens, fetches, or follows submitted destinations. URL checks extracted from analyzed email remain linked to that report.
- **Awareness training:** 12 fictional examples across three difficulties. Expected answers are a separate local teaching dataset; the rule engine runs independently. Session score and accuracy are stored locally as practice statistics, not real-world detection accuracy.
- **Reports:** download local JSON (`schemaVersion` 1.0) and multi-page PDF from email results/history and URL results/history.
- **History and feedback:** saved email reports can be reopened, rated, and deleted with confirmation.

## Local data and privacy

SQLite file: `data\cyberguard.sqlite3`. Email subject, sender, body, optional headers/recipient, parsed attachment metadata, findings, feedback, URL checks, training answers/scores, and any returned AI advisory are stored locally. Raw `.eml` file bytes are not stored as a separate upload. When the cloud option is checked, sender, subject, body, and supplied raw headers are sent to OpenAI; recipient and attachment metadata are not included. OpenAI request storage is disabled in the API request, but the provider's applicable data handling policies still apply. Do not send sensitive email unless you are authorized. Runtime logs omit email bodies and message contents.

The API is intentionally unauthenticated and loopback-only. Do not change its bind address or expose it to a network.

## API contracts

All endpoints are local under `/api`:

- `GET /health`, `GET /dashboard`, `GET /history`
- `POST /analyze` and `POST /analyze/preview` — JSON `{sender, recipient?, subject, body, rawHeaders?, attachments?}`
- `POST /feedback/:id`, `DELETE /history/:id`
- `POST /url/analyze` — `{urls:[string | {url, displayedText?}], analysisId?}`; `GET /url/history`
- `POST /eml/parse` — `{content}` (1 MB limit)
- `GET /training/scenarios`, `GET /training/stats`, `POST /training/sessions` — `{difficulty, answers:[{id,answer}]}`
- `GET /reports/:id.json`, `GET /reports/:id.pdf`, `GET /url/reports/:id.json`, `GET /url/reports/:id.pdf`

CORS is restricted to the configured local Vite origin. No API route performs remote URL inspection. Only the optional email advisory sends email text to the configured OpenAI endpoint, after the user checks the consent box for that analysis.

## Database migration

On startup, the API upgrades the existing `analyses` risk constraint to allow Critical, recalculates the stored risk label for old scores using the centralized bands, adds `metadata_json` when missing, and creates `url_analyses` and `training_sessions`. Existing report IDs, body, findings, and feedback are retained.

## Limitations

The detection rules are deterministic heuristics, not a validated security engine. They can miss threats and produce false positives. Authentication headers are only displayed/interpreted as supplied text; CyberGuard does not verify SPF, DKIM, or DMARC. The included `.eml` parser covers common text and multipart messages but is not a complete RFC MIME implementation. URL analysis is structural only and has no reputation or registered-domain database. PDF uses built-in local generation and standard fonts. There is no inbox integration, authentication, or remote synchronization. The optional OpenAI review requires user-provided credentials and a per-analysis opt-in; it is advisory only and does not change local scores.

## Build and tests

```powershell
npm run build
npm test
```

Tests use temporary SQLite databases and do not modify the persistent database.
