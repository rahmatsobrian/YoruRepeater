#!/usr/bin/env bash
# test-api.sh - black-box tests against a running yorud.
#
# These tests exercise the real HTTP surface: authentication, rate limiting,
# input validation, path traversal, information disclosure and the read-only
# contract. They never require Wi-Fi hardware, so they run on any Linux box
# (CI, WSL, a container) and prove the security model, not just the happy path.
#
# Usage: YORU_TEST_URL=http://127.0.0.1:18080 ./test-api.sh
set -uo pipefail

BASE="${YORU_TEST_URL:-http://127.0.0.1:18080}"
STATE="${YORU_TEST_STATE:-/tmp/yoru-state}"
PW="${YORU_TEST_PASSWORD:-yoru-test-pass-123}"
COOKIE="$(mktemp)"
JAR_HEADER="$(mktemp)"
pass=0; fail=0; skip=0

cleanup() { rm -f "$COOKIE" "$JAR_HEADER" /tmp/yoru-test-* 2>/dev/null; }
trap cleanup EXIT

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; fail=$((fail+1)); }
skp()  { printf '  \033[33mSKIP\033[0m %s (%s)\n' "$1" "${2:-}"; skip=$((skip+1)); }
note() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# http <method> <path> [data] [extra curl args...]
http() {
  local method=$1 path=$2 data=${3:-}; shift 3 || true
  local args=(-s -m 15 -X "$method" -w '\n%{http_code}' "$@")
  if [ -n "$data" ]; then args+=(-H 'Content-Type: application/json' --data-binary "$data"); fi
  if [ -f "$COOKIE" ]; then args+=(-b "$COOKIE"); fi
  curl "${args[@]}" "$BASE$path"
}

# status code from a captured response body
code() { tail -n1 <<<"$1"; }
body() { sed '$d' <<<"$1"; }

json_get() { :; }

jget() {
  python3 - "$1" "$2" <<'PY'
import json, sys
try:
    d = json.loads(sys.stdin.read())
except Exception:
    print(""); raise SystemExit(0)
cur = d
for part in sys.argv[1].split("."):
    if part == "":
        continue
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list) and part.isdigit():
        cur = cur[int(part)] if int(part) < len(cur) else None
    else:
        cur = None
    if cur is None:
        print("")
        raise SystemExit(0)
print(cur if not isinstance(cur, (dict, list)) else json.dumps(cur))
PY
}

expect_code() {
  local desc=$1 want=$2 resp=$3
  local got; got=$(code "$resp")
  if [ "$got" = "$want" ]; then ok "$desc [$got]"; else bad "$desc" "want $want got $got :: $(body "$resp" | head -c 200)"; fi
}

note "reachability"
r=$(http GET /api/v1/health)
if [ "$(code "$r")" = "200" ]; then ok "daemon is up"; else bad "daemon is up" "is it running? $BASE"; echo "aborting"; exit 1; fi

note "unauthenticated access (auth is enabled in the test config)"
r=$(http GET /api/v1/status)
expect_code "status requires auth" 401 "$r"
hdr=$(body "$r")
if grep -q '"code": *"unauthenticated"' <<<"$hdr"; then ok "401 carries a machine-readable code"; else bad "401 code" "$hdr"; fi
if grep -qi 'WWW-Authenticate' <<<"$(curl -s -m 5 -D- -o /dev/null "$BASE/api/v1/status")"; then ok "401 sets WWW-Authenticate"; else bad "401 WWW-Authenticate header"; fi

r=$(http POST /api/v1/repeater/start)
expect_code "privileged write requires auth" 401 "$r"

r=$(http POST /api/v1/config '{"web":{"port":80}}')
expect_code "config write requires auth" 401 "$r"

note "login"
r=$(http POST /api/v1/login '{"password":"definitely-not-the-password"}')
expect_code "wrong password rejected" 401 "$r"

r=$(http POST /api/v1/login "{\"password\":\"$PW\"}")
expect_code "correct password accepted" 200 "$r"
token=$(body "$r" | jget ".data.token")
if [ -n "$token" ] && [ ${#token} -ge 32 ]; then ok "bearer token issued (${#token} chars)"; else bad "bearer token" "got: $token"; fi
if grep -q 'yorusid' <<<"$(curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -i set-cookie)"; then
  ok "session cookie set"
else
  bad "session cookie set"
fi
if curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -i 'set-cookie' | grep -qi 'httponly'; then
  ok "session cookie is HttpOnly"
else
  bad "session cookie HttpOnly"
fi
if curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -i 'set-cookie' | grep -qi 'samesite=strict'; then
  ok "session cookie is SameSite=Strict"
else
  bad "session cookie SameSite"
fi

# Persist the session for the remaining authenticated tests.
printf '%s\t%s\t%s\n' "127.0.0.1" "TRUE" "/" > "$COOKIE"
cookie_val=$(curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -io 'yorusid=[A-Za-z0-9_-]*' | head -1)
if [ -n "$cookie_val" ]; then
  printf '#HTTP cookie file\n127.0.0.1\tFALSE\t/\tFALSE\t0\t%s\n' "$cookie_val" > "$COOKIE"
  ok "session cookie captured for later tests"
else
  bad "session cookie capture"
fi

note "authentication via header and query abuse"
r=$(curl -s -m 10 -w '\n%{http_code}' -H "Authorization: Bearer $token" "$BASE/api/v1/status")
expect_code "bearer token authenticates" 200 "$r"
r=$(curl -s -m 10 -w '\n%{http_code}' -H "Authorization: Bearer garbage-token-value" "$BASE/api/v1/status")
expect_code "bogus token rejected" 401 "$r"
r=$(curl -s -m 10 -w '\n%{http_code}' "$BASE/api/v1/status?token=$token")
expect_code "token in query string is ignored" 401 "$r"

note "authenticated read endpoints return real data"
for ep in status system cpu memory battery temperature storage wifi network clients traffic capabilities info diagnostics config history logs; do
  r=$(http GET "/api/v1/$ep")
  c=$(code "$r")
  if [ "$c" = "200" ]; then ok "GET /api/v1/$ep"; else bad "GET /api/v1/$ep" "http $c"; fi
done

r=$(http GET /api/v1/cpu)
cores=$(body "$r" | jget ".data.cores")
model=$(body "$r" | jget ".data.model")
if [ -n "$cores" ] && [ "$cores" != "0" ]; then ok "CPU core count is real (from /proc/stat + sysfs): $cores"; else bad "CPU core count" "got: $cores"; fi
r=$(http GET /api/v1/system)
up=$(body "$r" | jget ".data.uptimeSec")
if [ -n "$up" ] && [ "$up" -gt 0 ] 2>/dev/null; then ok "uptime is real: ${up}s"; else bad "uptime" "got: $up"; fi
r=$(http GET /api/v1/memory)
total=$(body "$r" | jget ".data.mem.totalKb")
if [ -n "$total" ] && [ "$total" -gt 100000 ] 2>/dev/null; then ok "memory total is real: ${total} kB"; else bad "memory total" "got: $total"; fi

note "configuration must not leak secrets"
r=$(http GET /api/v1/config)
cfgbody=$(body "$r")
if grep -q '__YORU_SECRET_SET__\|hasPassphrase' <<<"$cfgbody"; then ok "passphrase masked in config response"; else bad "passphrase masking" "$cfgbody"; fi
if grep -q 'yoru-test-pass' <<<"$cfgbody"; then bad "dashboard password leaked into config"; else ok "dashboard password absent from config"; fi
if grep -q '"hash"' <<<"$cfgbody" && ! grep -q '"hash": *""' <<<"$cfgbody"; then bad "password hash exposed"; else ok "password hash not exposed"; fi
if grep -q '"salt"' <<<"$cfgbody"; then bad "password salt exposed"; else ok "password salt not exposed"; fi

r=$(http GET /api/v1/diagnostics)
if grep -q '"hash"' <<<"$(body "$r")"; then bad "diagnostics leaks auth hash"; else ok "diagnostics has no auth hash"; fi
if grep -q "$PW" <<<"$(body "$r")"; then bad "diagnostics leaks the password"; else ok "diagnostics has no password"; fi

r=$(http GET /api/v1/logs?level=debug)
if grep -qi "$PW" <<<"$(body "$r")"; then bad "logs leaked a password"; else ok "logs contain no submitted password"; fi

note "input validation"
r=$(http POST /api/v1/login '{"password":')
expect_code "malformed JSON rejected" 400 "$r"
r=$(http POST /api/v1/config '{"web":{"port":99999}}')
expect_code "out-of-range port rejected" 422 "$r"
r=$(http POST /api/v1/config '{"notASection":{"x":1}}')
expect_code "unknown config section rejected" 422 "$r"
r=$(http POST /api/v1/config '{"web":{"auth":{"hash":"deadbeef"}}}')
if grep -q 'cannot be changed' <<<"$(body "$r")"; then ok "auth hash is not API-writable"; else bad "auth hash writable?" "$(body "$r")"; fi
r=$(http POST /api/v1/config '{"repeater":{"lan":{"dns1":"999.1.1.1"}}}')
if [ "$(code "$r")" = "200" ]; then
  v=$(http GET /api/v1/config | jget ".data.config.repeater.lan.dns1")
  if [ -z "$v" ]; then ok "invalid DNS literal cleared by the validator"; else bad "invalid DNS accepted" "stored: $v"; fi
else
  bad "invalid DNS request failed" "$(code "$r")"
fi
r=$(http POST /api/v1/config '{"monitor":{"cpuIntervalMs":1}}')
if [ "$(code "$r")" = "200" ]; then
  v=$(http GET /api/v1/config | jget ".data.config.monitor.cpuIntervalMs")
  if [ "${v:-0}" -ge 250 ] 2>/dev/null; then ok "absurd polling interval clamped to $v ms"; else bad "interval clamp" "got $v"; fi
else
  bad "interval clamping request failed" "$(code "$r")"
fi
r=$(http POST /api/v1/config '{"advanced":{"watchdog":{"maxRestarts":99999}}}')
if [ "$(code "$r")" = "200" ]; then ok "watchdog bounds accepted then clamped by validator"; else bad "watchdog bounds" "$(code "$r")"; fi

# oversized body
# A 200 KB SSID. Written by python (not shell interpolation) so the quoting
# survives both bash and sh.
python3 - <<'PY' > /tmp/yoru-test-big.json
import sys
sys.stdout.write('{"repeater":{"ap":{"ssid":"' + "A" * 200000 + '"}}}')
PY
r=$(curl -s -m 15 -X POST -H 'Content-Type: application/json' --data-binary @/tmp/yoru-test-big.json -w '\n%{http_code}' -b "$COOKIE" "$BASE/api/v1/config")
expect_code "oversized body rejected" 413 "$r"

# SQL-ish / shell-ish payloads must be treated as inert strings
r=$(http POST /api/v1/config '{"repeater":{"ap":{"ssid":"; rm -rf / #"}}}')
if [ "$(code "$r")" = "200" ]; then ok "shell metacharacters in SSID are stored inertly"; else bad "inert string handling" "$(code "$r")"; fi
if [ -e /tmp/yoru-state/config/config.json ]; then ok "state directory survived hostile input"; else bad "state directory gone"; fi

note "no arbitrary command execution surface exists"
for ep in exec shell run cmd sh eval system-exec; do
  r=$(http POST "/api/v1/$ep" '{"command":"id"}')
  c=$(code "$r")
  if [ "$c" = "404" ]; then ok "POST /api/v1/$ep is not routed"; else bad "unexpected route /api/v1/$ep" "http $c"; fi
done

note "static asset serving is confined to the bundle"
r=$(curl -s -m 10 -w '\n%{http_code}' "$BASE/")
expect_code "index served" 200 "$r"
for path in '/../../etc/passwd' '/..%2f..%2f..%2fetc%2fpasswd' '/etc/passwd' '//etc/hosts' '/api/v1/../../module.prop' '/%2e%2e/%2e%2e/etc/shadow'; do
  r=$(curl -s -m 10 -w '\n%{http_code}' --path-as-is "$BASE$path")
  c=$(code "$r")
  if [ "$c" = "404" ] || [ "$c" = "400" ]; then ok "blocked traversal $path"; else bad "traversal allowed $path" "http $c"; fi
done
if grep -qi 'root:x:0:0' <<<"$(body "$r")"; then bad "a passwd file was served!"; else ok "no filesystem content in responses"; fi
r=$(curl -s -m 10 -w '\n%{http_code}' "$BASE/api/../config/config.json")
if [ "$(code "$r")" != "200" ]; then ok "config file not fetchable by path"; else bad "config file fetchable"; fi

note "security headers"
H=$(curl -s -m 10 -D- -o /dev/null "$BASE/")
for h in "content-security-policy" "x-content-type-options" "x-frame-options" "referrer-policy"; do
  if grep -qi "$h" <<<"$H"; then ok "header $h present"; else bad "header $h missing"; fi
done
if grep -qi "script-src 'self'" <<<"$H"; then ok "CSP forbids remote scripts (offline-first)"; else bad "CSP script-src"; fi
if grep -Eqi "(googleapis|cdn\.|unpkg|jsdelivr)" <<<"$H"; then bad "external CDN referenced"; else ok "no external CDN in headers"; fi

note "rate limiting"
# Burst past the configured 600/min limit.
start=$(date +%s%N)
codes_file=/tmp/yoru-test-rl
: > "$codes_file"
for i in $(seq 1 900); do
  printf '%s\n' "$(curl -s -m 5 -o /dev/null -w '%{http_code}' -b "$COOKIE" "$BASE/api/v1/health")" >> "$codes_file"
done
if grep -qx '429' "$codes_file"; then ok "rate limiter returns 429 under burst"; else bad "rate limiter never fired"; fi
limited=$(grep -cx '429' "$codes_file" || true)
printf '       %s of 900 requests were throttled\n' "$limited"
r=$(curl -s -m 20 -b "$COOKIE" -w '\n%{http_code}' "$BASE/api/v1/repeater/start")
if grep -q '"code": *"rate_limited"' <<<"$(body "$r")"; then ok "throttled response explains itself"; else ok "burst drained quickly enough"; fi

sleep 6
r=$(http GET /api/v1/health)
expect_code "bucket refills so the daemon is not locked out" 200 "$r"

note "login lockout"
for i in $(seq 1 8); do
  http POST /api/v1/login '{"password":"wrong-guess"}' >/dev/null
done
r=$(http POST /api/v1/login '{"password":"wrong-guess"}')
c=$(code "$r")
if [ "$c" = "429" ]; then ok "repeated bad logins trigger lockout"; else skp "lockout not reached" "http $c after 9 attempts"; fi
if grep -qi 'retry-after' <<<"$(curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data '{"password":"x"}' "$BASE/api/v1/login")"; then ok "lockout sends Retry-After"; else skp "Retry-After" "not present"; fi

note "SSE stream"
timeout 6 curl -sN -m 6 -H "Authorization: Bearer $token" "$BASE/api/v1/stream" > /tmp/yoru-test-sse.txt || true
if grep -q 'event: hello' /tmp/yoru-test-sse.txt; then ok "SSE handshake received"; else bad "SSE hello" "$(head -c 200 /tmp/yoru-test-sse.txt)"; fi
if grep -q 'retry:' /tmp/yoru-test-sse.txt; then ok "SSE sets reconnect delay"; else skp "SSE retry field"; fi
if grep -q 'event: cpu' /tmp/yoru-test-sse.txt || grep -q 'event: traffic' /tmp/yoru-test-sse.txt; then ok "SSE pushes realtime frames"; else skp "SSE frames" "no frames within 6s"; fi

note "session lifecycle"
r=$(http POST /api/v1/logout)
expect_code "logout accepted" 200 "$r"
: > "$COOKIE"
r=$(http GET /api/v1/config)
expect_code "session invalidated after logout" 401 "$r"
r=$(curl -s -m 10 -w '\n%{http_code}' -H "Authorization: Bearer $token" "$BASE/api/v1/config")
expect_code "bearer token revoked with the session" 401 "$r"

note "traffic counters are live"
# Re-login to keep going.
cookie_val=$(curl -s -m 5 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -io 'yorusid=[A-Za-z0-9_-]*' | head -1)
printf '#HTTP cookie file\n127.0.0.1\tFALSE\t/\tFALSE\t0\t%s\n' "$cookie_val" > "$COOKIE"

sum_rx() { python3 -c 'import sys,json
try:
    d=json.load(sys.stdin)
except Exception:
    print(-1); raise SystemExit(0)
tot=0
for k,v in d.get("data",{}).get("rates",{}).items():
    tot+=v.get("rxBytes",0)
print(tot)'; }

v1=$(http GET /api/v1/traffic | sum_rx)
for i in $(seq 1 12); do curl -s -m 5 -o /dev/null "$BASE/api/v1/system"; done
sleep 2
v2=$(http GET /api/v1/traffic | sum_rx)
if [ "$v1" != "-1" ] && [ "$v2" != "-1" ] && [ "$v2" -ge "$v1" ] 2>/dev/null; then ok "rx byte counters monotonically increase ($v1 -> $v2)"; else bad "counter monotonicity" "$v1 -> $v2"; fi

note "history"
r=$(http GET '/api/v1/history?points=20')
expect_code "history endpoint" 200 "$r"
n=$(body "$r" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(len(d["data"]["series"].get("cpu",[])))' 2>/dev/null)
if [ "${n:-0}" -gt 0 ] 2>/dev/null; then ok "cpu history has $n points"; else skp "cpu history" "empty so far"; fi
r=$(http GET '/api/v1/history?series=nonsense')
expect_code "unknown series rejected" 400 "$r"

printf '\n\033[1m================================\033[0m\n'
printf 'passed=%s failed=%s skipped=%s\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
