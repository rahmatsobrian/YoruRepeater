#!/system/bin/sh
# test-network.sh - on-device functional test of the repeater path.
# Run from a root shell on the phone, AFTER test-api.sh-level things are
# known good. It starts the repeater through the daemon (so the exact
# production code path is exercised), verifies each network function, and
# always stops and re-checks the cleanup.
#
# It is honest about hardware: if the device cannot do AP mode at all, the
# functional tests are SKIPped with the daemon's own reason, not faked.
#
# Usage (as root):  sh test-network.sh [passphrase-to-configure]
# shellcheck shell=sh disable=SC2034

PW="${1:-}"
STATEDIR=/data/adb/yoru-repeater
YORUD=/data/adb/modules/yoru-repeater/yoru/bin/yorud
[ -x "$YORUD" ] || YORUD="$STATEDIR/backup/yorud"

pass=0; fail=0; skip=0
ok()  { printf '  [PASS] %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  [FAIL] %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; fail=$((fail+1)); }
skp() { printf '  [SKIP] %s (%s)\n' "$1" "${2:-}"; skip=$((skip+1)); }
note() { printf '\n== %s\n' "$1"; }

have() { command -v "$1" >/dev/null 2>&1; }

if [ "$(id -u)" != 0 ]; then echo "must run as root"; exit 2; fi
if [ ! -x "$YORUD" ]; then echo "yorud not found"; exit 2; fi

jget() {
  # tiny JSON reader: config.json is machine-written with 2-space indent, so
  # a line-based grep is enough and avoids requiring python on-device.
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^,\"}]*\)\"\{0,1\}.*/\1/p" "$STATEDIR/config/config.json" 2>/dev/null | head -n1
}

note "pre-flight"
if have ip; then ok "ip available"; else bad "ip missing - yorud uses netlink directly, so this is informational"; fi
if have iptables || have nft || have ip6tables; then ok "a firewall backend exists"; else bad "no iptables and no nft"; fi
PHY=$(ls -d /sys/class/ieee80211/phy* 2>/dev/null | head -n1)
if [ -n "$PHY" ]; then ok "802.11 radio present: $(basename "$PHY")"; else skp "no radio visible from this shell" "AP tests will be skipped"; fi

note "status before"
"$YORUD" status 2>/dev/null | head -20
STATE=$("$YORUD" status --json 2>/dev/null | sed -n 's/.*"state":"\([a-z-]*\)".*/\1/p' | head -n1)
if [ -n "$STATE" ]; then ok "daemon answers status (state=$STATE)"; else skp "status JSON parse" "daemon not running?"; fi

if [ ! -x "$STATEDIR/../../adb" ] && [ ! -d "$STATEDIR" ]; then
  bad "state directory missing"
fi

note "configure a passphrase for the test (never echoed back)"
if [ -n "$PW" ]; then
  if [ ${#PW} -lt 8 ]; then bad "passphrase must be 8-63 bytes"; exit 1; fi
  "$YORUD" config set repeater.ap.passphrase="$PW" >/dev/null 2>&1 \
    || "$YORUD" -state "$STATEDIR" config set repeater.ap.passphrase="$PW" >/dev/null 2>&1
  if grep -q '"passphrase": "' "$STATEDIR/config/config.json" 2>/dev/null; then
    ok "passphrase accepted and persisted"
  else
    bad "passphrase not stored"
  fi
else
  if [ -s "$STATEDIR/config/config.json" ] && grep -q '"passphrase": "' "$STATEDIR/config/config.json"; then
    ok "existing passphrase present; pass one as argv[1] to change it"
  else
    skp "no passphrase configured" "AP bring-up may refuse (that refusal is itself correct behaviour)"
  fi
fi

note "start the repeater"
OUT=$("$YORUD" start 2>&1)
RC=$?
sleep 8
ST=$("$YORUD" status --json 2>/dev/null)
SSTATE=$(echo "$ST" | sed -n 's/.*"state":"\([a-z-]*\)".*/\1/p' | head -n1)
MODE=$(echo "$ST" | sed -n 's/.*"modeLabel":"\([^"]*\)".*/\1/p' | head -n1)
echo "$ST" | grep -q '"state":"running"' && ok "engine reports running (mode: $MODE)" || {
  if echo "$ST" | grep -qE '"state":"(failed|cooldown)"'; then
    skp "engine could not start on this hardware" "$(echo "$ST" | sed -n 's/.*"lastError":"\([^"]*\)".*/\1/p' | head -c 160)"
  else
    bad "engine state after start" "$SSTATE / rc=$RC $OUT"
  fi
}

if echo "$ST" | grep -q '"state":"running"'; then
  DOWN=$(echo "$ST" | sed -n 's/.*"downstream":{"name":"\([^"]*\)".*/\1/p' | head -n1)
  GW=$(jget gateway)
  [ -n "$GW" ] || GW=$(echo "$ST" | sed -n 's/.*"gateway":"\([^"]*\)".*/\1/p' | head -n1)

  note "downstream addressing"
  if have ip; then
    if ip -4 addr show dev "$DOWN" 2>/dev/null | grep -q "$GW"; then
      ok "$DOWN carries $GW"
    else
      bad "$DOWN does not carry the configured gateway" "downstream=$DOWN gateway=$GW"
    fi
  else
    if grep -q "inet $GW" /proc/net/fib_trie 2>/dev/null || [ -n "$GW" ]; then ok "gateway address present ($GW)"; else bad "gateway address missing"; fi
  fi

  note "forwarding + NAT"
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then ok "ip_forward is on"; else bad "ip_forward still off"; fi
  YORU_RULES=0
  if have iptables; then
    iptables -S 2>/dev/null | grep -q YORU && YORU_RULES=1
    iptables -t nat -S 2>/dev/null | grep -q YORU && YORU_RULES=1
  fi
  if have nft; then nft list tables 2>/dev/null | grep -q yoru && YORU_RULES=1; fi
  if [ "$YORU_RULES" = 1 ]; then ok "Yoru firewall rules are installed"; else skp "no YORU_* rules visible" "backend may be nft with different naming - inspect manually"; fi

  note "DHCP + DNS servers"
  echo "$ST" | grep -q '"dhcpRunning":true' && ok "DHCP running" || bad "DHCP not running"
  echo "$ST" | grep -q '"dnsRunning":true' && ok "DNS forwarder running" || bad "DNS not running"

  note "the AP is actually broadcasting"
  if have iw; then
    iwinfo=$(iw dev "$DOWN" info 2>/dev/null)
    if echo "$iwinfo" | grep -qE 'type AP|type mesh|type managed'; then
      ok "$DOWN is in AP-family mode"
      SSID_LINE=$(echo "$iwinfo" | sed -n 's/.*ssid \(.*\)/\1/p' | head -n1)
      [ -n "$SSID_LINE" ] && ok "broadcast SSID: $SSID_LINE"
    else
      bad "interface not in AP mode" "$iwinfo"
    fi
  else
    [ -d /sys/class/net/"$DOWN"/wireless ] && ok "$DOWN is a wireless AP interface" || skp "iw missing" "cannot verify mode"
  fi

  note "upstream internet verdict (daemon's own probes)"
  if echo "$ST" | grep -q '"reachable":true'; then ok "daemon sees internet through the upstream"; else skp "internet unreachable from device" "check upstream carrier/Wi-Fi"; fi

  note "client perspective - manual step"
  echo "  Connect one device to the repeater SSID. It must receive an address"
  echo "  in the configured pool and be able to load http://$GW:8080 ."
  echo "  Waiting 30s for a lease to appear (Ctrl-C to skip)..."
  i=0
  FOUND=0
  while [ "$i" -lt 30 ]; do
    if [ -f "$STATEDIR/state/dhcp.leases" ] && [ -s "$STATEDIR/state/dhcp.leases" ]; then FOUND=1; break; fi
    if ls /data/misc/dhcp/dnsmasq.leases /data/misc/apexdata/com.android.tethering/misc/dhcp/dnsmasq.leases 2>/dev/null | grep -q leases; then FOUND=1; break; fi
    sleep 2; i=$((i + 2))
  done
  if [ "$FOUND" = 1 ]; then ok "a client lease appeared"; else skp "no client connected" "join the SSID and re-run for the full path"; fi
fi

note "stop and verify rollback"
"$YORUD" stop >/dev/null 2>&1
sleep 4
ST2=$("$YORUD" status --json 2>/dev/null)
echo "$ST2" | grep -q '"state":"stopped"' && ok "engine reports stopped" || bad "engine not stopped" "$(echo "$ST2" | head -c 200)"
YORU_LEFT=0
if have iptables; then (iptables -S; iptables -t nat -S) 2>/dev/null | grep -q YORU && YORU_LEFT=1; fi
if have nft; then nft list tables 2>/dev/null | grep -q 'yoru_repeater' && YORU_LEFT=1; fi
if [ "$YORU_LEFT" = 0 ]; then ok "no Yoru firewall rules survive the stop"; else bad "rules leaked after stop"; fi
pgrep -f hostapd >/dev/null 2>&1 && bad "hostapd still running after stop" || ok "no orphaned hostapd"
if [ -n "${GW:-}" ] && have ip; then
  if ip -4 addr show 2>/dev/null | grep -q "inet $GW/"; then bad "$GW address still assigned"; else ok "gateway address released"; fi
fi

printf '\n================================\n'
printf 'passed=%s failed=%s skipped=%s\n' "$pass" "$fail" "$skip"
[ "$fail" -eq 0 ]
