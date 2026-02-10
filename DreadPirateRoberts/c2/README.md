# C2 System Documentation

## System Components

### 1. Server Implementation
- WebSocket server with TLS encryption
- Command and control interface
- Client management system
- Command execution and response handling

### 2. Client Implementation
- WebSocket client with TLS support
- Command execution capabilities
- File upload/download functionality
- Heartbeat mechanism

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
   cd c2
   ./build.sh
   ```
   This will:
   - Generate self-signed TLS certificates
   - Build the server
   - Build the client

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

### Client Configuration (config.json)
```json
{
  "server_url": "wss://localhost:8443",
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

### Server Commands
1. View connected clients
2. Execute commands:
   - `ping`: Check client connectivity
   - `exec`: Execute shell commands
   - `fetch`: Download from URL
   - `upload`: Upload files

### Client Features
1. Automatic reconnection
2. Command queuing
3. File operations
4. Heartbeat monitoring

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