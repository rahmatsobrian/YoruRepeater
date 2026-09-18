#!/usr/bin/env bash
# Dev helper: stop the test daemon started by run-daemon.sh
set -uo pipefail
if [ -f /tmp/yorud.pid ]; then
  PID=$(cat /tmp/yorud.pid)
  kill "$PID" 2>/dev/null
  sleep 1
  kill -9 "$PID" 2>/dev/null
  echo "stopped pid $PID"
  rm -f /tmp/yorud.pid
else
  pkill -f '/tmp/yorud' 2>/dev/null && echo "killed stray yorud" || echo "no pid file, nothing running"
fi
