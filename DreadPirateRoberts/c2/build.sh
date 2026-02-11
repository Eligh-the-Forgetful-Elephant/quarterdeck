#!/bin/bash
# Build C2 server + client (and certs). Run from DreadPirateRoberts/c2.
# Use ./build-all.sh to also build the web UI.
set -e
C2_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$C2_ROOT"

# Use default GOROOT when env has invalid GOROOT (e.g. from g-install when ~/.go missing)
if [ -n "$GOROOT" ] && [ ! -d "$GOROOT" ]; then unset GOROOT; fi

chmod +x generate_certs.sh 2>/dev/null || true
chmod +x server/build.sh client/build.sh 2>/dev/null || true

echo "Generating TLS certificates..."
./generate_certs.sh

echo "Building Go server..."
./server/build.sh

echo "Building Go client..."
./client/build.sh

echo "Build complete!"
echo "  Server: cd server && ./c2server"
echo "  Client: cd client && ./client" 