# haxortools

O.MG cable + C2 workspace. Single C2 lives in **DreadPirateRoberts/c2/**.

## Layout

- **DreadPirateRoberts/c2/** – Server, client, web-ui, Docker. Build and run from here.
- **DreadPirateRoberts/c2/view/** – Static content served at **GET /view**.
- **DreadPirateRoberts/c2/macros/** – Keyboard (e.g. O.MG) payload scripts; loader hits **GET /sync** (base64-encoded).
- **tools/controller/** – `controller.cpp` – HTTP dead-drop implant (adapt to pull tasking from our C2).
- **tools/transposition/** – TEMPLARS cipher for payload/config encoding.
- **http_proxy.py** – Optional HTTP proxy for other testing.

## Build and run the C2

Requires: Go 1.21+, OpenSSL. For the web UI: Node/npm.

**Build server + client (and certs):**
```bash
cd DreadPirateRoberts/c2
./build.sh
```
`build.sh` unsets an invalid `GOROOT` so the Go build works on this machine even when `GOROOT` points at a missing directory.

**Build everything (including web UI):**
```bash
cd DreadPirateRoberts/c2
./build-all.sh
```

**Run:**
```bash
cd server && ./c2server    # terminal 1
cd client && ./client      # terminal 2 (edit config if needed)
```
For the web UI: `cd web-ui && npx serve -s build -l 3000` or `REACT_APP_API_URL=https://localhost:8443 npm start`.


## Endpoints

- **GET /sync** – Returns base64-encoded run script (decode and execute on target).
- **GET /view** – Serves static content from `c2/view/`.
- **WS /live** – WebSocket for connected clients.

## Operator (when server is running)

Stdin REPL: **list** | **use** \<session-id\> | **exec** \<command\> | **exit**

- `list` – show connected sessions (id + remote addr).
- `use <id>` – select session for exec.
- `exec <cmd>` – send command to selected session; output appears when the client responds.

Macros and loader: see `DreadPirateRoberts/c2/macros/README.md`.
