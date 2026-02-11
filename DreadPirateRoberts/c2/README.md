# C2 System Documentation

## System Components

### 1. Server Implementation
- WebSocket server with TLS encryption
- Command and control interface
- Client management system
- Command execution and response handling

### 2. Client Implementation
- **Go client** (cross‑platform): WebSocket with TLS, auth, `exec` and `ping`; auto‑reconnect.
- **PowerShell implant** (Windows): Served via GET /sync; `exec` via cmd.exe; auto‑reconnect.
- File upload/download: supported via operator API and implants when enabled (see Web UI File Manager).

## Requirements

1. Go 1.21 or later
2. OpenSSL (for certificate generation)
3. Required Go packages:
   ```bash
   go get github.com/gorilla/websocket
   ```

## Setup Instructions

1. Install dependencies:
   ```bash
   # Install Go dependencies
   go get github.com/gorilla/websocket
   
   # Install OpenSSL (if not already installed)
   # Ubuntu/Debian
   sudo apt-get install openssl
   
   # macOS
   brew install openssl
   ```

2. Build the system:
   ```bash
   cd DreadPirateRoberts/c2
   ./build.sh
   ```
   This will:
   - Generate self-signed TLS certificates (server/ and client/)
   - Build the server (`server/c2server`)
   - Build the client (`client/client`)

   **Build everything (including web UI):**
   ```bash
   cd DreadPirateRoberts/c2
   ./build-all.sh
   ```
   Requires: Go, OpenSSL, Node/npm. Fixes invalid `GOROOT` automatically so the Go build works on this machine.

3. Configure the server:
   ```bash
   cd server
   # Edit config.json if needed
   ./c2server
   ```

4. Configure the client:
   ```bash
   cd client
   # Edit config.json if needed
   ./client
   ```

## Configuration

### Server Configuration (config.json)
```json
{
  "port": 8443,
  "cert_file": "server.crt",
  "key_file": "server.key",
  "client_id": "default_client",
  "client_secret": "change_this_secret"
}
```

### Client Configuration (config.json, in client directory)
```json
{
  "server_url": "wss://localhost:8443/live",
  "client_id": "default_client",
  "client_secret": "change_this_secret",
  "cert_file": "server.crt"
}
```

## Security Considerations

1. TLS Encryption
   - All communications are encrypted
   - Self-signed certificates are used by default
   - Consider using valid certificates in production

2. Authentication
   - Basic client ID and secret authentication
   - Change default credentials in production

3. Command Security
   - Commands are executed with system permissions
   - Implement proper command validation
   - Consider command whitelisting

## Usage

### Operator (stdin or HTTP API)
- **list** – View connected sessions (GET /op/sessions).
- **use** \<id\> – Select session (stdin only).
- **exec** \<cmd\> – Run shell command on selected session (POST /op/exec).
- **kill** – Drop a session (POST /op/kill; see API).
- **health** – GET /op/health for server status.
- **Session history** – GET /op/sessions/history returns the last 100 past sessions (id, addr, first_seen, last_seen), persisted to `c2_sessions.jsonl` across restarts.
- **File operations** – Upload, download, and list directory on a session via POST /op/upload, /op/download, /op/listdir when the implant supports them (Go client and PowerShell implant do). Use the Web UI File Manager or the API; see RUNBOOK and WEB_UI_API.md.

### Client Features
- Automatic reconnection (30s backoff).
- Exec and ping; file upload/download via API when supported by implant.

## Troubleshooting

1. Connection Issues
   - Check server port availability
   - Verify TLS certificate
   - Check network connectivity

2. Command Execution
   - Verify client permissions
   - Check command syntax
   - Review error logs

3. File Operations
   - Verify file permissions
   - Check disk space
   - Review network bandwidth 