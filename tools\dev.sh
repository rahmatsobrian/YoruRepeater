#!/usr/bin/env bash
# Developer helper for the Windows host: runs Go checks inside WSL.
# Usage: wsl -d Ubuntu-24.04 -- bash <repo>/tools/dev.sh <command>
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DAEMON="$REPO/src/daemon"
export PATH="/opt/go/bin:$PATH"
export GOFLAGS="-mod=mod"
export GOCACHE="${GOCACHE:-/tmp/yoru-gocache}"
export GOPATH="${GOPATH:-/tmp/yoru-gopath}"
export CGO_ENABLED=0

norm() {
  # Force LF endings for everything that ships in the module or gets compiled.
  local dirs=()
  for d in module src web tests tools; do
    [ -d "$REPO/$d" ] && dirs+=("$REPO/$d")
  done
  [ ${#dirs[@]} -eq 0 ] && return 0
  find "${dirs[@]}" -type f \
    \( -name '*.sh' -o -name '*.go' -o -name '*.json' -o -name '*.css' -o -name '*.js' \
       -o -name '*.html' -o -name '*.svg' -o -name '*.prop' -o -name '*.rule' -o -name '*.md' \) \
    -print0 2>/dev/null | xargs -0 -r sed -i 's/\r$//'
}

case "${1:-check}" in
  norm) norm ;;
  vet) norm; cd "$DAEMON"; go vet ./... ;;
  cc) norm; cd "$DAEMON"; go build ./internal/... ;;
  build) norm; cd "$DAEMON"; go build -o /tmp/yorud ./cmd/yorud; echo "built /tmp/yorud" ;;
  test) norm; cd "$DAEMON"; go test ./... ;;
  fmt) norm; cd "$DAEMON"; gofmt -l -w . ;;
  cross)
    norm; cd "$DAEMON"
    mkdir -p "$REPO/module/bin"
    GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$REPO/module/bin/yorud-arm64" ./cmd/yorud
    GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="-s -w" -o "$REPO/module/bin/yorud-arm" ./cmd/yorud
    ls -l "$REPO/module/bin"
    ;;
  *) echo "unknown command: $1" >&2; exit 2 ;;
esac
