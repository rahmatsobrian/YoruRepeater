#!/usr/bin/env bash
# Syntax-check every WebUI JavaScript file with node --check.
set -u
cd "$(dirname "$0")/../src/web/js" || exit 1
rc=0
for f in *.js; do
  if node --check "$f" 2>/tmp/jscheck.err; then
    echo "OK   $f"
  else
    echo "FAIL $f"
    cat /tmp/jscheck.err
    rc=1
  fi
done
exit $rc
