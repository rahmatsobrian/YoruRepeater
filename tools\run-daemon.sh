#!/usr/bin/env bash
# Dev helper: run the daemon in WSL for manual/API testing.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
STATE="${YORU_TEST_STATE:-/tmp/yoru-state}"
PORT="${YORU_TEST_PORT:-18080}"
export PATH="/opt/go/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export GOFLAGS="-mod=mod"
export GOCACHE=/tmp/yoru-gocache
export CGO_ENABLED=0

cd "$REPO/src/daemon" || exit 1
mkdir -p "$STATE/config" "$STATE/logs" "$STATE/state" "$STATE/run"
go build -o /tmp/yorud ./cmd/yorud || exit 1

# Fresh config with auth enabled and a known password for testing.
cat > "$STATE/config/config.json" <<JSON
{
  "schemaVersion": 2,
  "repeater": { "enabled": false, "autoStart": false },
  "web": {
    "port": $PORT, "bind": "loopback", "readonlyEnabled": false,
    "auth": { "enabled": true, "algorithm": "pbkdf2-sha256", "iterations": 20000 }
  },
  "monitor": { "cpuIntervalMs": 500, "memIntervalMs": 500, "trafficIntervalMs": 500, "clientsIntervalMs": 1000 }
}
JSON
/tmp/yorud -state "$STATE" password 'yoru-test-pass-123' >/dev/null 2>&1 || { echo "password bootstrap failed"; exit 1; }
nohup setsid /tmp/yorud -state "$STATE" -wait-boot=false -no-autostart -port "$PORT" \
  > /tmp/yorud.out 2>&1 < /dev/null &
echo $! > /tmp/yorud.pid
disown 2>/dev/null || true
sleep 2
if ! kill -0 "$(cat /tmp/yorud.pid)" 2>/dev/null; then
  echo "daemon failed to start:"; cat /tmp/yorud.out; exit 1
fi
echo "pid=$(cat /tmp/yorud.pid) port=$PORT state=$STATE"
echo "$STATE" > /tmp/yoru-test-state
echo "$PORT" > /tmp/yoru-test-port
