#!/usr/bin/env bash
# Dev helper: build the probe and run one section with full tracing.
# Usage: run-probe.sh <section> [timeout-seconds]
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SECTION="${1:-caps}"
TMO="${2:-40}"
export PATH="/opt/go/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export GOFLAGS="-mod=mod"
export GOCACHE=/tmp/yoru-gocache
export CGO_ENABLED=0
cd "$REPO/src/daemon"

echo "== building"
if ! go build -o /tmp/probe-bin ./cmd/probe; then
  echo "BUILD FAILED"; exit 1
fi
echo "== running section=$SECTION (timeout ${TMO}s)"
timeout --preserve-status "$TMO" /tmp/probe-bin -section="$SECTION" > "/tmp/probe-$SECTION.json" 2> "/tmp/probe-$SECTION.err"
rc=$?
echo "exit=$rc"
echo "-- stderr --"
cat "/tmp/probe-$SECTION.err"
echo "-- stdout size: $(wc -c < "/tmp/probe-$SECTION.json") bytes"
