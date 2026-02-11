#!/bin/bash
# Build everything: certs, C2 server, C2 client, and web UI.
# Run from DreadPirateRoberts/c2. Requires: go, openssl, node/npm.
set -e
C2_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$C2_ROOT"

echo "=== C2 server + client + certs ==="
./build.sh

echo ""
echo "=== Web UI ==="
cd web-ui
if [ ! -d node_modules ]; then
  echo "Installing npm dependencies..."
  npm install
fi
echo "Building web UI..."
npm run build
cd ..

echo ""
echo "All builds complete!"
echo "  Server:  cd server && ./c2server"
echo "  Client:  cd client && ./client"
echo "  Web UI:  npm run build already done; serve with: cd web-ui && npx serve -s build -l 3000"
echo "  Or dev:  cd web-ui && REACT_APP_API_URL=https://localhost:8443 npm start"
