#!/usr/bin/env bash
# Dev helper: dump a probe section in a compact, human-readable form.
# Usage: probe-dump.sh [net|cpu|mem|battery|thermal|storage]
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SECTION="${1:-net}"
export PATH="/opt/go/bin:$PATH"
export GOFLAGS="-mod=mod"
export GOCACHE="${GOCACHE:-/tmp/yoru-gocache}"
export CGO_ENABLED=0
cd "$REPO/src/daemon"
go run ./cmd/probe -section="$SECTION" > /tmp/probe.json

if [ "$SECTION" = "net" ]; then
  python3 - <<'PY'
import json
d = json.load(open('/tmp/probe.json'))
print("links:")
for l in d.get('links', []):
    st = l.get('statistics') or {}
    print("  %-14s idx=%-3d up=%-5s run=%-5s oper=%-14s mac=%-17s rx=%-10s tx=%-10s" % (
        l['name'], l['index'], l['up'], l['running'], l.get('operState',''), l.get('mac',''),
        st.get('rxBytes','-'), st.get('txBytes','-')))
print("addresses:")
for a in d.get('addresses', []):
    print("  %-12s %-5s %-24s scope=%-7s label=%s" % (a['iface'], a['family'], a['cidr'], a['scope'], a.get('label','')))
print("routes:")
for r in d.get('routes', [])[:16]:
    print("  %-5s %-19s via=%-15s dev=%-8s table=%-7s proto=%-7s metric=%s" % (
        r['family'], r['dst'], r.get('gateway',''), r.get('dev',''), r['table'], r['protocol'], r['metric']))
print("dns:", [x['server']+"("+x['source']+")" for x in d.get('dns', [])])
print("ipv6Enabled:", d.get('ipv6Enabled'), " hostname:", d.get('hostname'))
print("counts: links=%d addrs=%d routes=%d" % (len(d.get('links',[])), len(d.get('addresses',[])), len(d.get('routes',[]))))
PY
else
  python3 -m json.tool /tmp/probe.json
fi
