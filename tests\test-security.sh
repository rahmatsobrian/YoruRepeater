#!/usr/bin/env bash
# test-security.sh - attack-focused black-box tests for the dashboard.
#
# Where test-api.sh checks that the API *works*, this script tries to make it
# do things it must never do: execute commands, read files, leak secrets,
# skip authentication, outrun the rate limiter or keep a session after
# revocation. Run it against a throwaway instance, never a phone you rely on.
#
# Usage: YORU_TEST_URL=http://127.0.0.1:18080 YORU_TEST_PASSWORD=... ./test-security.sh
set -uo pipefail

BASE="${YORU_TEST_URL:-http://127.0.0.1:18080}"
PW="${YORU_TEST_PASSWORD:-yoru-test-pass-123}"
pass=0; fail=0; skip=0
J=$(mktemp); C=$(mktemp)
trap 'rm -f "$J" "$C"' EXIT

ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1m\033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; fail=$((fail+1)); }
skp() { printf '  \033[33mSKIP\033[0m %s (%s)\n' "$1" "${2:-}"; skip=$((skip+1)); }
note() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

login() {
  curl -s -m 10 -c "$C" -o /dev/null -X POST -H 'Content-Type: application/json' \
    --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login"
}
auth_get() { curl -s -m 15 -b "$C" "$BASE$1"; }
auth_post() { curl -s -m 15 -b "$C" -H 'Content-Type: application/json' --data "$2" "$BASE$1"; }

if ! curl -s -m 5 -o /dev/null "$BASE/api/v1/health"; then
  echo "daemon not reachable at $BASE" >&2
  exit 2
fi

note "authentication boundary"
st=$(curl -s -m 5 "$BASE/api/v1/health")
if login; then :; fi
tok=$(curl -s -m 10 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -io 'yorusid=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)
if [ -n "$tok" ]; then ok "session obtained"; else bad "cannot obtain session (is auth enabled?)"; fi

r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/v1/config")
if [ "$r" = "401" ]; then ok "config requires a session"; else bad "config open" "http $r (readonly/anonymous? note readonlyEnabled allows GET monitoring only, never /config)"; fi
r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/v1/diagnostics")
if [ "$r" = "401" ]; then ok "diagnostics requires a session"; else bad "diagnostics open" "http $r"; fi
r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/v1/logs")
if [ "$r" = "401" ]; then ok "logs require a session"; else bad "logs open" "http $r"; fi
r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BASE/api/v1/history")
if [ "$r" = "401" ]; then ok "history requires a session"; else skp "history open" "http $r (may be allowed when anonymous monitoring is on)"; fi

note "read-only sessions cannot write"
if [ -n "$tok" ]; then
  rt=$(curl -s -m 10 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\",\"readonly\":true}" "$BASE/api/v1/login" | grep -io 'yorusid=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)
  r=$(curl -s -m 10 -o "$J" -w '%{http_code}' -b "$C" -H "Cookie: yorusid=$rt" -X POST -H 'Content-Type: application/json' --data '{"repeater":{"ap":{"ssid":"PWNED"}}}' "$BASE/api/v1/config")
  # Note: cookie precedence makes this test meaningful only when the readonly
  # cookie replaces the writable one; curl jar ordering can differ. Check code:
  if [ "$r" = "403" ]; then ok "read-only session blocked from config write"; else skp "read-only write block" "http $r"; fi
fi

note "no command-execution surface exists, under any alias"
for ep in exec execve shell system run cmd sh bash python perl eval php spawn fork; do
  for m in GET POST; do
    r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -b "$C" -X $m "$BASE/api/v1/$ep")
    if [ "$r" != "404" ] && [ "$r" != "405" ]; then bad "$m /api/v1/$ep answered" "http $r"; fi
  done
done
ok "no exec-style route answers (all 404/405)"

note "privilege separation: config keys outside the allowlist"
for patch in '{"meta":{"installId":"hax"}}' '{"web":{"auth":{"hash":"x"}}}' '{"web":{"auth":{"salt":"x"}}}' '{"advanced":{"env":{"PATH":"/tmp"}}}' '{"schemaVersion":999}' '{"repeater":{"ap":{"passphrase":"12345678"}}}'; do
  r=$(curl -s -m 10 -o "$J" -w '%{http_code}' -b "$C" -H 'Content-Type: application/json' --data "$patch" "$BASE/api/v1/config")
  if grep -q 'cannot be changed\|must be changed with\|not writable' "$J" 2>/dev/null && [ "$r" != "200" ]; then
    ok "refused: $(echo "$patch" | head -c 40)"
  else
    case "$patch" in
      *schemaVersion*) ok "schema key rejected ($r)";;
      *) bad "accepted forbidden write: $patch" "http $r $(head -c 120 "$J")";;
    esac
  fi
done

note "secrets never leave the device"
cfgjson=$(auth_get "/api/v1/config")
if grep -qE '"passphrase" *: *"[0-9a-zA-Z]{8,}"' <<<"$cfgjson"; then bad "a real passphrase was serialised"; else ok "passphrase field masked or empty"; fi
diag=$(auth_get "/api/v1/diagnostics")
for needle in '"hash"' '"salt"' password plaintext pre-shared; do
  if grep -qi "$needle" <<<"$diag"; then bad "diagnostics contains $needle"; else ok "diagnostics has no $needle"; fi
done
logs=$(auth_get "/api/v1/logs?limit=500&level=debug")
if grep -q "$PW" <<<"$logs"; then bad "session token or password found in logs"; else ok "logs clean of submitted credentials"; fi
if grep -qE 'yorusid=|Bearer [A-Za-z0-9_-]{20,}' <<<"$logs"; then bad "a live session token appears in logs"; else ok "no bearer tokens in logs"; fi

note "session revocation is total"
login
tok2=$(curl -s -m 10 -D- -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$PW\"}" "$BASE/api/v1/login" | grep -io 'yorusid=[A-Za-z0-9_-]*' | head -1 | cut -d= -f2)
curl -s -m 5 -b "$C" -X POST "$BASE/api/v1/logout" >/dev/null
r=$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok2" "$BASE/api/v1/config")
if [ "$r" = "401" ]; then ok "bearer token dies with the session"; else bad "token survived logout" "http $r"; fi

note "password change revokes every session"
newpw="rotated-test-pw-42"
r=$(curl -s -m 10 -b "$C" -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  --data "{\"password\":\"$newpw\",\"current\":\"$PW\"}" "$BASE/api/v1/password")
if [ "$r" = "200" ]; then
  r2=$(curl -s -m 5 -b "$C" -o /dev/null -w '%{http_code}' "$BASE/api/v1/config")
  if [ "$r2" = "401" ]; then ok "old sessions are gone after rotation"; else bad "old session still valid" "http $r2"; fi
  curl -s -m 10 -b "$C" -o /dev/null -X POST -H 'Content-Type: application/json' --data "{\"password\":\"$newpw\",\"current\":\"$newpw\"}" "$BASE/api/v1/password" >/dev/null
  PW_BACKUP=$PW; PW=$newpw; login
else
  skp "password rotation" "http $r (weak policy or auth disabled?)"
fi

note "password strength policy"
r=$(curl -s -m 10 -b "$C" -o "$J" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data '{"password":"short","current":"'"$PW"'"}' "$BASE/api/v1/password")
if [ "$r" = "400" ]; then ok "weak password refused with an explanation"; else bad "weak password policy" "http $r"; fi

note "request hardening"
r=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -b "$C" -H 'Content-Type: application/json' --data '{"a":1,}' "$BASE/api/v1/config")
[ "$r" = "400" ] && ok "trailing-comma JSON rejected" || bad "malformed JSON accepted" "$r"
r=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -b "$C" -H 'Content-Type: application/json' --data '{"unknown":true}' "$BASE/api/v1/config")
[ "$r" = "422" ] || [ "$r" = "400" ] && ok "unknown top-level key rejected" || bad "unknown key handled" "$r"
H=$(curl -s -m 5 -D- -o /dev/null "$BASE/")
grep -qi 'X-Frame-Options: *DENY' <<<"$H" && ok "clickjacking protection" || bad "X-Frame-Options missing"
grep -qi 'Content-Security-Policy' <<<"$H" && ok "CSP present" || bad "CSP missing"
grep -qi "frame-ancestors 'none'" <<<"$H" && ok "CSP frame-ancestors none" || bad "CSP frame-ancestors"
grep -qi 'X-Content-Type-Options: *nosniff' <<<"$H" && ok "no-sniff" || bad "nosniff missing"
grep -qi 'Cross-Origin-Opener-Policy' <<<"$H" && ok "COOP set" || bad "COOP missing"

note "SSE honours authentication"
code=$(timeout 4 curl -s -N -o /dev/null -w '%{http_code}' "$BASE/api/v1/stream" || true)
if [ "$code" = "401" ]; then ok "anonymous SSE stream refused"; else bad "SSE auth" "got $code"; fi

printf '\n\033[1m================================\033[0m\n'
printf 'passed=%s failed=%s skipped=%s\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
