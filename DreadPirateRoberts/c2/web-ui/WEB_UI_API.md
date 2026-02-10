# Web UI and server API

The server exposes an operator API so the web UI (or any client) can list sessions and run commands without a TTY.

## API base URL

Point the UI at the server (same port as TLS):

- **Development:** `https://localhost:8443` (ignore self-signed cert in browser).
- Set `REACT_APP_API_URL` to that URL when building/serving the UI.
- If the server uses `op_token`, set `REACT_APP_OP_TOKEN` so the UI sends `X-Op-Token` on requests.

## Endpoints

| Method | Path         | Auth           | Body / response |
|--------|--------------|----------------|------------------|
| GET    | /op/sessions | X-Op-Token or ?k= | List of `{id, addr}` |
| POST   | /op/exec     | X-Op-Token or ?k= | Body: `{session_id, command}`. Response: `{session_id, command_id, status, output, error}` (blocks until client responds or 90s). |

CORS is enabled for `/op/*` so the browser can call the server from another origin (e.g. UI on port 3000, server on 8443).

## Wiring the UI

- **Clients** page: `GET /op/sessions` and render rows (id, addr).
- **Console** page: dropdown from `/op/sessions`, command input, on Send do `POST /op/exec` and append the response output to the console log.

See RUNBOOK.md for full server and API usage.
