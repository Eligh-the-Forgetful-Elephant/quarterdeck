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
| GET    | /op/sessions           | X-Op-Token or ?k= | List of `{id, addr, platform}` (live sessions only). |
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

Optional header **X-Op-Identity** sets operator id for audit log when server config `op_identity` is not set.

CORS is enabled for `/op/*` so the browser can call the server from another origin (e.g. UI on port 3000, server on 8443).

## Wiring the UI

- **Dashboard:** `GET /op/health` for server reachable and session count.
- **Clients:** `GET /op/sessions`, Kill button calls `POST /op/kill`.
- **Session history:** `GET /op/sessions/history` for past sessions (id, addr, first_seen, last_seen); refresh button to reload.
- **Console:** dropdown from `/op/sessions`, command input, `POST /op/exec`, Run creds = `POST /op/creds`.
- **Screenshot:** session + Capture = `POST /op/screenshot`, display image.
- **Processes:** session + Refresh = `POST /op/processlist`, Kill = `POST /op/prockill`.
- **Keylog:** session + Start / Stop and get log = `POST /op/keylog/start`, `POST /op/keylog/stop`.
- **Audit:** `GET /op/audit`, Export report = `GET /op/audit?format=csv`.
- **File Manager:** session + path, List = `POST /op/listdir`, Download = `POST /op/download`, Upload = `POST /op/upload`.
- **Settings:** display-only for REACT_APP_API_URL and op token.

See RUNBOOK.md for full server and API usage.
