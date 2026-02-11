#!/bin/bash
# Build C2 server. Use from server/ or from c2/ (as ./server/build.sh).
# Fixes broken GOROOT so build works on this machine.
set -e
if [ -n "$GOROOT" ] && [ ! -d "$GOROOT" ]; then unset GOROOT; fi
cd "$(dirname "$0")"
go build -o c2server .
echo "Server built: ./c2server"
