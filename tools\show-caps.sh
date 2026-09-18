#!/usr/bin/env bash
# Dev helper: render the capability probe results as a table.
set -euo pipefail
FILE="${1:-/tmp/probe.json}"
python3 - "$FILE" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for c in d.get("capabilities", []):
    note = c.get("reason") or c.get("detail") or ""
    print("%-24s %-9s %-14s %s" % (c["id"], c["state"], c["source"], note[:72]))
print()
print("SUMMARY:", json.dumps(d.get("summary"), indent=1))
PY
