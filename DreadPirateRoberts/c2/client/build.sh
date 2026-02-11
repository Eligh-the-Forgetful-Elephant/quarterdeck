#!/bin/bash
# Build C2 client. Use from client/ or from c2/ (as ./client/build.sh).
# Fixes broken GOROOT so build works on this machine.
set -e
if [ -n "$GOROOT" ] && [ ! -d "$GOROOT" ]; then unset GOROOT; fi
cd "$(dirname "$0")"
go build -o client .
echo "Client built: ./client"
