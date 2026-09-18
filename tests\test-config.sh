#!/usr/bin/env bash
# test-config.sh - configuration engine tests (defaults, migration, validation,
# secret handling, file permissions). Runs offline with a locally built yorud;
# no daemon, no network, no root needed.
#
# Usage: YORUD=/path/to/yorud ./test-config.sh
set -uo pipefail
export PATH="/opt/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH"

YORUD="${YORUD:-}"
if [ -z "$YORUD" ]; then
  if command -v yorud >/dev/null 2>&1; then YORUD="$(command -v yorud)"; else
    echo "building host yorud..." >&2
    HERE="$(cd "$(dirname "$0")/.." && pwd)"
    ( cd "$HERE/src/daemon" && CGO_ENABLED=0 go build -o /tmp/yorud-test ./cmd/yorud ) || { echo "build failed" >&2; exit 2; }
    YORUD=/tmp/yorud-test
  fi
fi

pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1m\033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; fail=$((fail+1)); }
note() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
CFGDIR="$TMP/state/config"
CFG="$CFGDIR/config.json"
mkdir -p "$CFGDIR"

jrun() { "$YORUD" -state "$TMP/state" password 'correcthorse123' >/dev/null 2>&1; }

note "first run creates defaults safely"
jrun
if [ -f "$CFG" ]; then ok "config.json created"; else bad "no config written"; fi
perm=$(stat -c '%a' "$CFG" 2>/dev/null || stat -f '%Lp' "$CFG")
if [ "$perm" = "600" ]; then ok "config file is 0600 (contains a Wi-Fi key)"; else bad "config permissions" "$perm"; fi
if python3 -c "import json;json.load(open('$CFG'))"; then ok "default config is valid JSON"; else bad "default config unparseable"; fi
schema=$(python3 -c "import json;print(json.load(open('$CFG'))['schemaVersion'])")
if [ "$schema" = "2" ]; then ok "schema version is current (2)"; else bad "schema" "$schema"; fi
dirmode=$(stat -c '%a' "$TMP/state/config" 2>/dev/null || stat -f '%Lp' "$TMP/state/config")
if [ "$dirmode" = "700" ]; then ok "config directory is 0700"; else bad "config directory mode" "$dirmode"; fi

note "password hashing"
hash=$(python3 -c "import json;a=json.load(open('$CFG'))['web']['auth'];print(a['hash'])")
salt=$(python3 -c "import json;a=json.load(open('$CFG'))['web']['auth'];print(a['salt'])")
if [ -n "$hash" ] && [ "$hash" != "None" ] && [ ${#hash} -eq 64 ]; then ok "PBKDF2 verifier stored (64 hex chars)"; else bad "auth hash" "$hash"; fi
if [ -n "$salt" ] && [ ${#salt} -ge 32 ]; then ok "random salt stored"; else bad "salt" "$salt"; fi
if grep -q 'correcthorse123' "$CFG"; then bad "plaintext password persisted!"; else ok "no plaintext password on disk"; fi

note "short passwords are refused"
"$YORUD" -state "$TMP/state" password 'sh0rt' >"$TMP/short.out" 2>&1
if [ $? -ne 0 ]; then ok "6-char password rejected"; else bad "short password accepted"; fi
"$YORUD" -state "$TMP/state" password 'correcthorse123' >"$TMP/longpw.out" 2>&1
if [ $? -eq 0 ]; then ok "valid re-set accepted (rotation works)"; else bad "password rotation rejected" "$(cat "$TMP/longpw.out")"; fi

note "legacy schema 1 migrates"
MIG="$TMP/mig/config"; mkdir -p "$MIG"
cat > "$MIG/config.json" <<'JSON'
{
  "schemaVersion": 1,
  "repeater": { "mode": "auto", "ap": { "ssid": "Old", "security": "wpa2-psk", "passphrase": "0123456789", "band": "2g", "channel": 6, "maxClients": 10 } ,
    "lan": { "gateway": "10.20.30.1", "prefix": 24, "dhcpStart": "10.20.30.10", "dhcpEnd": "10.20.30.50", "leaseMinutes": 60 } },
  "web": { "port": 9090, "passwordHash": "aaaa", "passwordSalt": "bbbb", "authIterations": 100000 },
  "monitor": { "refreshInterval": 3000 },
  "meta": { "firstRun": 1 }
}
JSON
"$YORUD" -state "$TMP/mig" password 'migrated-pass-1' >/dev/null 2>&1
if python3 - "$MIG/config.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
assert c["schemaVersion"] == 2, c["schemaVersion"]
assert c["web"]["port"] == 9090
assert c["monitor"]["cpuIntervalMs"] == 3000, c["monitor"]
assert c["monitor"]["batteryIntervalMs"] == 15000, c["monitor"]
assert "refreshInterval" not in c["monitor"]
assert "passwordHash" not in c["web"]
assert len(c["web"]["auth"]["hash"]) == 64          # legacy verifier preserved? no: replaced by new password
assert c["meta"]["migratedFrom"] == 1
assert c["repeater"]["ap"]["ssid"] == "Old"
print("ok")
PY
then ok "schema 1 -> 2 migration preserves values and promotes intervals"; else bad "migration output"; fi
if grep -q '"passwordHash"' "$MIG/config.json"; then bad "legacy field left behind"; else ok "legacy auth fields removed"; fi

note "corrupt config cannot crash the daemon"
BAD="$TMP/bad/config"; mkdir -p "$BAD"
printf '{"schemaVersion": 2, "repeater": {{{broken!!' > "$BAD/config.json"
"$YORUD" -state "$TMP/bad" password 'still-alive-1' >"$TMP/bad.out" 2>&1
rc=$?
if [ $rc -eq 0 ]; then ok "daemon functioned on a corrupt config (rc=0)"; else bad "corrupt config broke CLI" "rc=$rc $(head -2 "$TMP/bad.out")"; fi
if [ -f "$BAD/config.json.bad" ]; then ok "original corrupt file preserved as config.json.bad"; else bad "no backup of corrupt config"; fi
if python3 -c "import json;c=json.load(open('$BAD/config.json'));assert c['schemaVersion']==2"; then ok "defaults were written back cleanly"; else bad "no clean default written"; fi

note "future schema is preserved, never silently interpreted"
FUT="$TMP/fut/config"; mkdir -p "$FUT"
printf '{"schemaVersion": 99}' > "$FUT/config.json"
"$YORUD" -state "$TMP/fut" password 'future-pass-1' >/dev/null 2>&1
if [ -f "$FUT/config.json.bad" ] && grep -q '99' "$FUT/config.json.bad"; then
  ok "newer-than-supported config backed up intact as config.json.bad"
else
  bad "original future config was not preserved"
fi
if python3 -c "import json;c=json.load(open('$FUT/config.json'));assert c['schemaVersion']==2 and c['web']['port']>0"; then
  ok "daemon continued on safe defaults instead of guessing the new format"
else
  bad "future schema produced an invalid default config"
fi

note "validator bounds are enforced"
VAL="$TMP/val/config"; mkdir -p "$VAL"
cat > "$VAL/config.json" <<'JSON'
{ "schemaVersion": 2,
  "web": { "port": 99999, "sessionHours": 0, "rateLimitPerMin": 1 },
  "monitor": { "cpuIntervalMs": 5, "logMaxFiles": 500 },
  "repeater": { "mode": "telepathy", "lan": { "gateway": "1.2.3.4", "prefix": 33, "dhcpStart": "10.0.0.5", "dhcpEnd": "10.0.0.9" },
                "ap": { "ssid": "X", "security": "wep-wep", "channel": 999, "maxClients": 0 } } }
JSON
"$YORUD" -state "$TMP/val" password 'validator-test-1' >/dev/null 2>&1
python3 - "$VAL/config.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
w, m, r = c["web"], c["monitor"], c["repeater"]
assert 1 <= w["port"] <= 65535 and w["port"] != 99999, w["port"]
assert w["sessionHours"] >= 1
assert w["rateLimitPerMin"] >= 10
assert m["cpuIntervalMs"] >= 250
assert 1 <= m["logMaxFiles"] <= 20
assert r["mode"] in ("auto","repeater","hotspot","usb","ethernet","disabled"), r["mode"]
assert 16 <= r["lan"]["prefix"] <= 30
assert r["ap"]["security"] != "wep-wep"
assert 0 <= r["ap"]["channel"] <= 233
assert r["ap"]["maxClients"] >= 1
net = r["lan"]["gateway"].rsplit(".",1)[0]
assert r["lan"]["dhcpStart"].startswith(net), "DHCP range regenerated into subnet"
print("ok")
PY
if [ $? -eq 0 ]; then ok "every out-of-bounds value was clamped to a legal one"; else bad "validator did not normalise the config"; fi

# Subnet-vs-upstream conflict detection needs live routes and is verified on
# the device by test-network.sh; there is nothing honest to assert here.

printf '\n\033[1m================================\033[0m\n'
printf 'passed=%s failed=%s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
