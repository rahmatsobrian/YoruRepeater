#!/system/bin/sh
# Yoru Repeater - uninstall.sh
# Executed by the root manager as root after the module payload is removed
# from the mount list (so $MODPATH files are referenced before unmount on
# Magisk; on KernelSU/APatch this runs from the still-present directory).
#
# Contract (see docs/SECURITY.md): uninstall stops every Yoru process and
# removes every Yoru network artefact, but never destroys unrelated
# configuration, and keeps user settings unless explicitly asked to.
#
# shellcheck shell=sh disable=SC2034

STATEDIR=/data/adb/yoru-repeater
MODDIR=${0%/*}
BIN="$STATEDIR/backup/yorud"
LOG="$STATEDIR/logs/uninstall.log"

say() { ui_print "- $1" 2>/dev/null || echo "$1"; echo "$(date '+%F %T') uninstall: $1" >> "$LOG" 2>/dev/null; }

mkdir -p "$STATEDIR/logs" 2>/dev/null

# A copy of the binary is kept so cleanup can run after the module folder is
# gone. customize.sh places it there on upgrade; do it here too as a fallback.
if [ ! -x "$BIN" ] && [ -x "$MODDIR/yoru/bin/yorud" ]; then
  mkdir -p "$STATEDIR/backup" 2>/dev/null
  cp "$MODDIR/yoru/bin/yorud" "$BIN" 2>/dev/null
  chmod 0755 "$BIN" 2>/dev/null
fi

say "Stopping Yoru"
# Supervised shutdown first: the worker's SIGTERM path performs a full
# in-process rollback (firewall chains, addresses, DHCP/DNS, hostapd), which
# is far safer than removing rules externally.
if [ -f "$STATEDIR/state/supervise.pid" ]; then
  SPID=$(sed 's/[^0-9].*//' "$STATEDIR/state/supervise.pid" 2>/dev/null)
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null
fi
# Term any remaining workers/children, give them time to roll back cleanly.
pkill -f "yorud run" 2>/dev/null
pkill -f "yorud supervise" 2>/dev/null
i=0
while [ "$i" -lt 12 ]; do
  pgrep -f "yorud" >/dev/null 2>&1 || break
  sleep 1
  i=$((i + 1))
done
pkill -9 -f "yorud run" 2>/dev/null
pkill -9 -f "yorud supervise" 2>/dev/null

# Whatever is left (orphans, hostapd, a dnsmasq we lost track of) gets the
# scripted scrub, which only touches objects named YORU_* / yoru_*.
# The module folder may already be gone, so the installer keeps a backup copy
# of the scripts in the state directory.
CLEAN=""
for c in "$MODDIR/yoru/scripts/cleanup.sh" "$STATEDIR/backup/cleanup.sh"; do
  [ -f "$c" ] && CLEAN="$c" && break
done
if [ -n "$CLEAN" ]; then
  sh "$CLEAN" "$STATEDIR" >> "$LOG" 2>&1
fi

say "Removing temporary state (your configuration is kept)"
rm -rf "$STATEDIR/run" 2>/dev/null
rm -f "$STATEDIR/state/supervise.pid" "$STATEDIR/state/cli.token" \
     "$STATEDIR/state/clients.json" "$STATEDIR/state/supervisor-halted" \
     "$STATEDIR/state/last-boot" 2>/dev/null
rm -f "$STATEDIR/logs/service.log" "$STATEDIR/logs/supervise.out" 2>/dev/null
[ -d "$STATEDIR/logs" ] && ls "$STATEDIR/logs" >/dev/null 2>&1 || rm -rf "$STATEDIR/logs" 2>/dev/null

# User data is NOT deleted by default. Create the marker first and it goes too:
#   touch /data/adb/yoru-repeater/remove-on-uninstall
if [ -f "$STATEDIR/remove-on-uninstall" ]; then
  say "remove-on-uninstall marker found: deleting configuration as requested"
  rm -rf "$STATEDIR" 2>/dev/null
else
  say "Keeping $STATEDIR/config (delete it manually to reset everything)"
fi

say "Done. Reboot recommended if you reinstall a different network module."
exit 0
