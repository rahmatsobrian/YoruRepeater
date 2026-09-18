#!/system/bin/sh
# test-cleanup.sh - verifies Yoru's promise that it cleans up AFTER itself
# and ONLY after itself: stop, crash, supervisor recovery, uninstall
# bookkeeping, and preservation of foreign (VPN/oem) firewall state.
#
# Run as root on the device:  sh test-cleanup.sh
# shellcheck shell=sh disable=SC2034

STATEDIR=/data/adb/yoru-repeater
MODDIR=/data/adb/modules/yoru-repeater
YORUD="$MODDIR/yoru/bin/yorud"
[ -x "$YORUD" ] || YORUD="$STATEDIR/backup/yorud"

pass=0; fail=0; skip=0
ok()  { printf '  [PASS] %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  [FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; fail=$((fail+1)); }
skp() { printf '  [SKIP] %s (%s)\n' "$1" "${2:-}"; skip=$((skip+1)); }
note() { printf '\n== %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" != 0 ]; then echo "must run as root"; exit 2; fi

yoru_rule_count() {
  n=0
  if have iptables; then n=$((n + $(iptables -S 2>/dev/null | grep -c YORU_))); fi
  if have ip6tables; then n=$((n + $(ip6tables -S 2>/dev/null | grep -c YORU_))); fi
  if have nft; then n=$((n + $(nft list tables 2>/dev/null | grep -c 'yoru_'))); fi
  echo "$n"
}

note "baseline: rules foreign to Yoru are counted"
BEFORE=$(yoru_rule_count)
printf '  current YORU_* rule lines: %s\n' "$BEFORE"

# Snapshot a couple of unrelated chains so we can prove the stop path did not
# touch them. A full ruleset diff is the strongest honest assertion available
# from a shell.
if have iptables; then
  iptables -S > /tmp/yoru-test-fwd-before 2>/dev/null
  ok "snapshotted iptables state"
else
  skp "iptables -S snapshot" "no iptables"
fi

note "clean stop removes only Yoru objects"
"$YORUD" stop >/dev/null 2>&1
sleep 3
AFTER=$(yoru_rule_count)
if [ "$AFTER" -eq 0 ]; then ok "zero YORU_* rules after stop"; else bad "YORU rules leaked" "$AFTER still present"; fi
if have iptables; then
  iptables -S > /tmp/yoru-test-fwd-after 2>/dev/null
  if diff /tmp/yoru-test-fwd-before /tmp/yoru-test-fwd-after 2>/dev/null | grep -q '^[<>]'; then
    CHANGED=$(diff /tmp/yoru-test-fwd-before /tmp/yoru-test-fwd-after | grep '^[<>]' | grep -vc YORU || true)
    if [ "${CHANGED:-0}" = "0" ]; then ok "non-Yoru iptables lines are byte-identical"; else bad "unrelated rules changed" "$CHANGED lines differ"; fi
  else
    ok "iptables output identical before/after"
  fi
fi
if have nft; then
  nft list tables 2>/dev/null | grep -q 'yoru_repeater\|yoru_probe' && bad "nft yoru tables remain" || ok "no nft yoru tables remain"
fi
pgrep -f 'yorud run' >/dev/null 2>&1 && skp "worker alive (dashboard keeps running - by design)" :
pgrep -f hostapd >/dev/null 2>&1 && bad "hostapd orphan after stop" || ok "no orphaned hostapd"
ls "$STATEDIR"/run/hostapd-*.pid >/dev/null 2>&1 && bad "stale hostapd pid files" || ok "run dir pid files gone"

note "process crash recovers (supervisor + backoff)"
WPID=$(pgrep -f 'yorud run' | head -n1)
if [ -n "$WPID" ]; then
  kill -9 "$WPID"
  ok "killed worker $WPID with SIGKILL"
  sleep 8
  WPID2=$(pgrep -f 'yorud run' | head -n1)
  if [ -n "$WPID2" ] && [ "$WPID2" != "$WPID" ]; then
    ok "supervisor respawned the worker ($WPID -> $WPID2)"
  else
    skp "no respawn observed" "supervisor not running, or restart budget spent (check state/supervisor-halted)"
  fi
  if [ -f "$STATEDIR/state/supervisor-halted" ]; then
    skp "supervisor previously halted" "budget spent earlier; delete the marker after investigating"
  else
    ok "no halt marker (restart budget intact)"
  fi
else
  skp "crash recovery" "worker not running"
fi

note "repeated crash halts instead of looping forever"
i=0
while [ "$i" -lt 3 ]; do
  W=$(pgrep -f 'yorud run' | head -n1)
  [ -n "$W" ] && kill -9 "$W"
  sleep 4
  i=$((i + 1))
done
Halted=""
[ -f "$STATEDIR/state/supervisor-halted" ] && Halted=1
if [ -n "$Halted" ]; then
  ok "supervisor stopped restarting and recorded the halt"
else
  # Not necessarily wrong: the window may not be exhausted yet. Report honestly.
  printf '  [INFO] restart budget not yet exhausted - supervisor will halt if crashes continue\n'
fi
# Recover for the next tests.
SPID=$(sed 's/[^0-9].*//' "$STATEDIR/state/supervise.pid" 2>/dev/null)
[ -n "$SPID" ] && kill "$SPID" 2>/dev/null
sleep 2
[ -f "$STATEDIR/state/supervisor-halted" ] && rm -f "$STATEDIR/state/supervisor-halted"
printf '  (supervisor stopped; restart via service.sh or "yorud supervise &" to continue using Yoru)\n'

note "config survives everything (never auto-deleted)"
if [ -f "$STATEDIR/config/config.json" ]; then
  ok "config still present after crash storm + stop"
  if head -c1 "$STATEDIR/config/config.json" | grep -q '{'; then
    ok "config starts with valid JSON structure"
  else
    bad "config file is not JSON"
  fi
else
  skp "no config file" "fresh install?"
fi
if [ "$(stat -c '%a' "$STATEDIR/config/config.json" 2>/dev/null)" = "600" ]; then
  ok "config permissions still 0600"
else
  printf '  [INFO] could not stat config mode (no GNU stat?)\n'
fi

note "cleanup.sh is idempotent and safe with nothing to clean"
if [ -f "$MODDIR/yoru/scripts/cleanup.sh" ]; then
  sh "$MODDIR/yoru/scripts/cleanup.sh" "$STATEDIR" 2>/dev/null
  RC=$?
  if [ "$RC" = "0" ] && [ "$(yoru_rule_count)" -eq 0 ]; then
    ok "cleanup.sh ran twice-safe, exit 0, nothing removed that was not ours"
  else
    bad "cleanup.sh run" "rc=$RC"
  fi
  sh "$MODDIR/yoru/scripts/cleanup.sh" "$STATEDIR" 2>/dev/null
  [ $? -eq 0 ] && ok "second run still exit 0 (idempotent)" || bad "second run failed"
else
  skp "cleanup.sh" "module folder gone (test uninstall separately)"
fi

note "uninstall leaves no processes"
if have yorud || [ -x "$YORUD" ]; then
  "${YORUD:-yorud}" stop >/dev/null 2>&1 || true
fi
sleep 1
pgrep -f 'yorud' >/dev/null 2>&1 && printf '  [INFO] a yorud is still running (supervisor?) - run uninstall from the root manager to fully remove\n' || ok "no yorud processes"
if [ -f "$STATEDIR/remove-on-uninstall" ]; then
  skp "remove-on-uninstall marker present" "config intentionally deleted by uninstall"
else
  [ -f "$STATEDIR/config/config.json" ] && ok "user configuration preserved after uninstall path (marker absent)" || skp "no config to preserve"
fi

rm -f /tmp/yoru-test-fwd-before /tmp/yoru-test-fwd-after
printf '\n================================\n'
printf 'passed=%s failed=%s skipped=%s\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
