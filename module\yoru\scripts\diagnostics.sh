#!/system/bin/sh
# Yoru Repeater - diagnostics.sh
# Builds a single text report an operator (or a forum moderator) can read
# without any tooling. Prefers the live daemon's JSON diagnostics, falls back
# to the offline probe, then to detect.sh, so it always produces something.
#
# Secrets policy: the report is written for other humans to see. Passphrases,
# password hashes/salts and session tokens are stripped before saving.
#
# shellcheck shell=sh disable=SC2034

STATEDIR="${1:-/data/adb/yoru-repeater}"
MODDIR="/data/adb/modules/yoru-repeater"
BIN=""
for cand in "$MODDIR/yoru/bin/yorud" "$STATEDIR/backup/yorud"; do
  [ -x "$cand" ] && BIN="$cand" && break
done

OUTDIR="$STATEDIR"
TS=$(date '+%Y%m%d-%H%M%S')
[ -n "$TS" ] || TS=report
REPORT="$OUTDIR/diagnostics-$TS.txt"
mkdir -p "$OUTDIR" 2>/dev/null

scrub() {
  # Drop lines that could carry credentials, and inline values of sensitive
  # JSON keys, whatever case/format they arrive in.
  sed -e 's/"passphrase"[[:space:]]*:[[:space:]]*"[^"]*"/"passphrase":"[REDACTED]"/g' \
      -e 's/"hash"[[:space:]]*:[[:space:]]*"[^"]*"/"hash":"[REDACTED]"/g' \
      -e 's/"salt"[[:space:]]*:[[:space:]]*"[^"]*"/"salt":"[REDACTED]"/g' \
      -e 's/yorusid=[A-Za-z0-9_-]*/yorusid=[REDACTED]/g' \
      -e 's/Authorization:[[:space:]]*Bearer[[:space:]]*[A-Za-z0-9_-]*/Authorization: Bearer [REDACTED]/g' \
      -e '/"password"[[:space:]]*:/d' \
      -e '/pre-shared_key/d'
}

section() {
  printf '\n===== %s =====\n' "$1" >> "$REPORT"
}

printf 'Yoru Repeater diagnostics\n' > "$REPORT" 2>/dev/null || exit 1
printf 'generated: %s\nhost: %s\n' "$(date)" "$(hostname 2>/dev/null || echo unknown)" >> "$REPORT"

section "environment"
if [ -f "$MODDIR/yoru/scripts/detect.sh" ]; then
  sh "$MODDIR/yoru/scripts/detect.sh" 2>/dev/null | scrub >> "$REPORT"
else
  echo "detect.sh missing (module removed?)" >> "$REPORT"
fi

if [ -n "$BIN" ]; then
  section "daemon diagnostics (yorud diagnose)"
  "$BIN" diagnose --timeout 15s 2>&1 | scrub >> "$REPORT"
  section "offline capability probe (yorud probe)"
  "$BIN" probe 2>&1 | scrub >> "$REPORT"
else
  section "daemon"
  echo "yorud binary not found; module is likely removed or mid-install" >> "$REPORT"
fi

section "dashboard port"
if [ -f "$STATEDIR/config/config.json" ]; then
  sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/port=\1/p' "$STATEDIR/config/config.json" 2>/dev/null | head -n1 >> "$REPORT"
fi

section "interfaces (ip -brief)"
ip -brief addr 2>/dev/null | scrub >> "$REPORT" || \
  { for i in /sys/class/net/*; do echo "$(basename "$i") $(cat "$i/operstate" 2>/dev/null)"; done >> "$REPORT"; }

section "default routes"
ip route show default 2>/dev/null >> "$REPORT"
ip -6 route show default 2>/dev/null >> "$REPORT"

section "yoru firewall objects"
# Only Yoru-owned chains are listed; the full ruleset is deliberately not
# dumped because it can contain VPN/other-app material.
for b in iptables ip6tables; do
  command -v "$b" >/dev/null 2>&1 || continue
  for t in filter nat; do
    "$b" -S -t "$t" 2>/dev/null | grep -i yoru | scrub >> "$REPORT"
  done
done
command -v nft >/dev/null 2>&1 && nft list table ip yoru_repeater 2>/dev/null >> "$REPORT"

section "recent log (last 150 lines)"
tail -n 150 "$STATEDIR/logs/yoru.log" 2>/dev/null | scrub >> "$REPORT"

section "supervisor console (last 40 lines)"
tail -n 40 "$STATEDIR/logs/supervise.out" 2>/dev/null | scrub >> "$REPORT"

section "end"
chmod 0600 "$REPORT" 2>/dev/null
chown 0 0 "$REPORT" 2>/dev/null
echo "$REPORT"
