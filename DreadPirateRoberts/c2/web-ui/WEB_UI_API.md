# Web UI and server API

The server exposes an operator API so the web UI (or any client) can list sessions, run commands, and manage files without a TTY.

## API base URL

Point the UI at the server (same port as TLS):

- **Development:** `https://localhost:8443` (ignore self-signed cert in browser).
- Set `REACT_APP_API_URL` to that URL when building/serving the UI.
- If the server uses `op_token`, set `REACT_APP_OP_TOKEN` so the UI sends `X-Op-Token` on requests.

## Endpoints

| Method | Path                   | Auth            | Body / response |
|--------|------------------------|-----------------|------------------|
| GET    | /op/sessions           | X-Op-Token or ?k= | List of `{id, addr, platform, alias?}` (live sessions; alias set for provisioned clients). |
| GET    | /op/sessions/history   | X-Op-Token or ?k= | List of `{id, addr, platform, first_seen, last_seen}` (last 100, persisted). |
| GET    | /op/health             | X-Op-Token or ?k= | `{ok, sessions}` |
| GET    | /op/audit              | X-Op-Token or ?k= | Query: `?limit=200&format=csv` (optional). Returns JSON array of audit rows (ts, operator_id, action, session_id, technique_id, detail), or CSV attachment. |
| POST   | /op/exec      | X-Op-Token or ?k= | Body: `{session_id, command}`. Response: `{session_id, command_id, status, output, error}` (blocks up to 90s). |
| POST   | /op/kill      | X-Op-Token or ?k= | Body: `{session_id}`. Drops the session. |
| POST   | /op/upload    | X-Op-Token or ?k= | Body: `{session_id, path, content}` (content base64). Response: `{status, output, error}`. |
| POST   | /op/download  | X-Op-Token or ?k= | Body: `{session_id, path}`. Response: `{status, output, error}` (output is file content base64). |
| POST   | /op/listdir   | X-Op-Token or ?k= | Body: `{session_id, path}`. Response: `{status, output, error}` (output is JSON array of `{name, dir, size}`). |
| POST   | /op/screenshot | X-Op-Token or ?k= | Body: `{session_id}`. Response: `{status, output, error}` (output is base64 PNG). |
| POST   | /op/processlist | X-Op-Token or ?k= | Body: `{session_id}`. Response: `{status, output, error}` (output is JSON array of `{pid, ppid, user, name}`). |
| POST   | /op/prockill  | X-Op-Token or ?k= | Body: `{session_id, pid}`. Response: `{status, output, error}`. |
| POST   | /op/keylog/start | X-Op-Token or ?k= | Body: `{session_id}`. Response: `{status, output, error}`. |
| POST   | /op/keylog/stop  | X-Op-Token or ?k= | Body: `{session_id}`. Response: `{status, output, error}` (output is captured keystrokes). |
| POST   | /op/creds     | X-Op-Token or ?k= | Body: `{session_id}`. Response: `{status, output, error}` (stub; upload/exec your cred tool). |
| GET    | /op/c2log     | X-Op-Token or ?k= | Query: `?session_id=&limit=200&abridge=true`. Returns JSON array of `{ts, session_id, direction, detail}` (C2 traffic log). |
| GET    | /op/queue     | X-Op-Token or ?k= | Query: `?session_id=`. Response: `{session_id, queue: string[]}`. |
| POST   | /op/queue     | X-Op-Token or ?k= | Body: `{session_id, command}`. Appends command to session queue; next is sent when implant responds. |
| POST   | /op/queue/clear | X-Op-Token or ?k= | Body: `{session_id}`. Clears session command queue. |
| POST   | /op/provision | X-Op-Token or ?k= | Body: `{alias}`. Creates provisioned device; returns `{alias, client_id, client_secret, provision_str, server_url_hint}`. Paste provision_str into device config. |
| GET    | /op/session_config | X-Op-Token or ?k= | Query: `?session_id=`. Response: `{session_id, poll_seconds, fast_seconds}`. |
| POST   | /op/session_config | X-Op-Token or ?k= | Body: `{session_id, poll_seconds?, fast_seconds?}`. Sets per-session poll/timing hints. |

Optional header **X-Op-Identity** sets operator id for audit log when server config `op_identity` is not set.

CORS is enabled for `/op/*` so the browser can call the server from another origin (e.g. UI on port 3000, server on 8443).

## Wiring the UI

- **Dashboard:** `GET /op/health` for server reachable and session count.
- **Clients:** `GET /op/sessions`, Kill button calls `POST /op/kill`.
- **Session history:** `GET /op/sessions/history` for past sessions (id, addr, first_seen, last_seen); refresh button to reload.
- **Console:** dropdown from `/op/sessions`, command input, `POST /op/exec`, Run creds = `POST /op/creds`. Queue: `GET /op/queue`, Add to queue = `POST /op/queue`, Clear queue = `POST /op/queue/clear`.
- **Screenshot:** session + Capture = `POST /op/screenshot`, display image.
- **Processes:** session + Refresh = `POST /op/processlist`, Kill = `POST /op/prockill`.
- **Keylog:** session + Start / Stop and get log = `POST /op/keylog/start`, `POST /op/keylog/stop`.
- **Audit:** `GET /op/audit`, Export report = `GET /op/audit?format=csv`.
- **File Manager:** session + path, List = `POST /op/listdir`, Download = `POST /op/download`, Upload = `POST /op/upload`.
- **Settings:** display-only for REACT_APP_API_URL and op token; Provision: alias input, `POST /op/provision`, copy client_id/secret or provision_str.
- **C2 Log:** `GET /op/c2log` with optional session_id and limit; table of ts, session_id, direction, detail.

See RUNBOOK.md for full server and API usage.
