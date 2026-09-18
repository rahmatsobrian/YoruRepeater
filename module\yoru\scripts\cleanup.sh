#!/system/bin/sh
# Yoru Repeater - cleanup.sh
# Last-resort scrub of Yoru-owned network objects, used by uninstall and by
# operators after a crash. The daemon performs precise, recorded rollbacks
# itself; this script exists for when the daemon is gone.
#
# HARD RULES (docs/SECURITY.md):
#   - never flush a table, never delete a rule it did not name,
#   - only objects matching YORU_* / yoru_repeater are touched,
#   - every command is best-effort: absence is success.
#
# shellcheck shell=sh disable=SC2034

STATEDIR="${1:-/data/adb/yoru-repeater}"
RUN="$STATEDIR/run"
log() { echo "$(date '+%F %T') cleanup: $1" 1>&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 1. Yoru-spawned children (hostapd etc. via pid files)
# ---------------------------------------------------------------------------
if [ -d "$RUN" ]; then
  for pf in "$RUN"/*.pid; do
    [ -e "$pf" ] || continue
    pid=$(sed 's/[^0-9].*//' "$pf" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      log "stopping pid $pid ($(basename "$pf"))"
      kill "$pid" 2>/dev/null
      i=0
      while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 6 ]; do sleep 1; i=$((i + 1)); done
      kill -9 "$pid" 2>/dev/null
    fi
    rm -f "$pf" 2>/dev/null
  done
  # Orphaned hostapd carrying Yoru's control socket path in its arguments.
  pkill -f "hostapd.*yoru-repeater" 2>/dev/null
  rm -rf "$RUN/hostapd-ctrl" "$RUN"/hostapd-*.conf 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 2. Firewall objects owned by Yoru
# ---------------------------------------------------------------------------
YORU_CHAINS="YORU_REPEATER YORU_REPEATER_NAT YORU_ACC YORU_ISOLATE"

clean_ipt() {
  b=$1; t=$2
  # Remove jumps into Yoru chains from the built-in chains first, so nothing
  # references a chain we are about to delete. Repeat until no match remains.
  for ch in $YORU_CHAINS; do
    if have "$b"; then
      parent=FORWARD
      case "$ch" in
        YORU_REPEATER_NAT|YORU_ACC) parent=POSTROUTING ;;
      esac
      # YORU_ACC may also be referenced from FORWARD; try both harmlessly.
      for p in FORWARD POSTROUTING PREROUTING INPUT OUTPUT; do
        while "$b" -t "$t" -S "$p" 2>/dev/null | grep -q -- "-j $ch"; do
          "$b" -t "$t" -D "$p" -j "$ch" 2>/dev/null || break
        done
      done
      # Flush only the Yoru chain itself, then remove it.
      if "$b" -t "$t" -S "$ch" >/dev/null 2>&1; then
        log "removing $t chain $ch via $b"
        "$b" -t "$t" -F "$ch" 2>/dev/null
        "$b" -t "$t" -X "$ch" 2>/dev/null
      fi
    fi
  done
}

for b in iptables ip6tables; do
  have "$b" || continue
  clean_ipt "$b" filter
  clean_ipt "$b" nat
done

if have nft; then
  if nft list table ip yoru_repeater >/dev/null 2>&1; then
    log "deleting nft table ip yoru_repeater"
    nft delete table ip yoru_repeater 2>/dev/null
  fi
  if nft list table ip6 yoru_repeater >/dev/null 2>&1; then
    log "deleting nft table ip6 yoru_repeater"
    nft delete table ip6 yoru_repeater 2>/dev/null
  fi
  # Leftover probe table from capability checks (created and removed by the
  # daemon; removed here too if a crash interrupted it).
  nft list table ip yoru_probe >/dev/null 2>&1 && nft delete table ip yoru_probe 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 3. Addresses Yoru assigned (gateway only - read from the config)
# ---------------------------------------------------------------------------
GATEWAY=""
if [ -f "$STATEDIR/config/config.json" ]; then
  GATEWAY=$(sed -n 's/.*"gateway"[[:space:]]*:[[:space:]]*"\([0-9.]*\)".*/\1/p' "$STATEDIR/config/config.json" 2>/dev/null | head -n1)
fi
if [ -n "$GATEWAY" ] && have ip; then
  ip -o -4 addr show 2>/dev/null | grep -F "$GATEWAY" | while IFS= read -r l; do
    ifc=$(echo "$l" | awk '{print $2}')
    cidr=$(echo "$l" | sed 's/.*inet \([0-9./]*\).*/\1/')
    # Refuse to strip the address off a station interface: that is the
    # phone's own connectivity, which may coincidentally sit in the subnet.
    case "$ifc" in
      wlan*|rmnet*|ccmni*|apex*|dummy*|tun*|wg*)
        # Only remove from AP-typical names; leave everything else alone.
        case "$ifc" in
          ap[0-9]*|swlan[0-9]*|SoftAp*|p2p*)
            log "removing $cidr from $ifc"
            ip addr del "$cidr" dev "$ifc" 2>/dev/null
            ;;
          *) log "leaving $cidr on $ifc (not a Yoru-managed AP interface)" ;;
        esac
        ;;
      *)
        log "removing $cidr from $ifc"
        ip addr del "$cidr" dev "$ifc" 2>/dev/null
        ;;
    esac
  done
fi

# ---------------------------------------------------------------------------
# 4. Durable state Yoru owns
# ---------------------------------------------------------------------------
rm -f "$STATEDIR/state/dhcp.leases" 2>/dev/null
rm -f "$STATEDIR/state/last-hostapd" 2>/dev/null

log "cleanup complete"
exit 0
