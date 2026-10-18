# CyberGuard AI — local development

CyberGuard AI is a local-only prototype. The existing React interface is served by Vite; a Node.js HTTP API performs deterministic rule analysis and stores reports in SQLite using Node's built-in `node:sqlite` module. Email bodies are not sent to external services.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Node.js LTS (npm is included)
- Node.js 22.13 or newer (Node 24 LTS is recommended)

There is no Docker, Python, added backend package, or separately installed database server requirement. SQLite is included with the supported Node.js runtime.

## First-time setup

Open PowerShell in this project directory and install the frontend dependencies:

```powershell
npm install
Copy-Item .env.example .env
```

The `.env` file is optional. Defaults are frontend `127.0.0.1:5173`, API `127.0.0.1:8000`, and database `data/cyberguard.sqlite3`. Do not put secrets in `.env`; this prototype has no secret-bearing integrations.

## Start with one command

```powershell
powershell -ExecutionPolicy Bypass -File .\start-local.ps1 -OpenBrowser
```

The script starts both services as hidden local processes, checks the API and frontend, and prints the URL. Omit `-OpenBrowser` if you prefer to open the printed URL yourself. Stop services with:

```powershell
.\stop-local.ps1
```

The database file is stored at `data\cyberguard.sqlite3` in this project. It is ignored by Git and remains on this computer after stopping or restarting the app. The browser's in-memory feedback/history state has been replaced by server-backed SQLite records.

## Manual startup fallback

Use two PowerShell windows in the project directory.

Terminal 1 — local API:

```powershell
node .\server\app.js
```

Terminal 2 — local frontend:

```powershell
npm run dev -- --host 127.0.0.1 --strictPort
```

Open `http://127.0.0.1:5173/`. Press `Ctrl+C` in each terminal to stop its service.

The frontend sends API requests directly to the local `VITE_API_URL`; the API permits requests only from the configured local frontend origin. Both services bind to `127.0.0.1` only. If you change `API_PORT` in `.env`, update the port in `VITE_API_URL` as well.

## Features

- Explainable deterministic analysis rules with Low, Medium, and High risk bands.
- SQLite-backed reports and feedback.
- Analysis history can be opened and deleted from the interface.
- Input validation and user-visible API error messages.
- Local HTTP health endpoint at `/api/health`.

The analysis rules are an educational simulation, not a validated security engine. There is no authentication, real AI model, inbox integration, server-side account system, or cross-computer synchronization. The local API intentionally has no authentication because it binds only to loopback; do not change the bind address or expose it to a network.

## Build and tests

```powershell
npm run build
npm test
```

Tests use Node's built-in test runner and a temporary SQLite database; they do not use or modify the persistent database.

