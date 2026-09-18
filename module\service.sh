#!/system/bin/sh
# Yoru Repeater - service.sh
# Runs in Magisk/KernelSU/APatch's late_start service domain (root, post-boot).
# Its job: wait for a sane boot state, ensure WiFi STA is connected, then
# hand control to the yorud supervisor and get out of the way.
#
# shellcheck shell=sh disable=SC2034

MODDIR=${0%/*}
STATEDIR=/data/adb/yoru-repeater
BIN="$MODDIR/yoru/bin/yorud"
LOG="$STATEDIR/logs/service.log"
SUP_PID="$STATEDIR/state/supervise.pid"
WIFI_LOG="$STATEDIR/logs/wifi-reconnect.log"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') service: $1" >> "$LOG" 2>/dev/null
}

wlog() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') wifi: $1" >> "$WIFI_LOG" 2>/dev/null
}

# Operator kill switch, matching Magisk module conventions.
[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/skip_initrc" ] && exit 0
[ -f "$STATEDIR/disabled" ] && { log "disabled marker present, not starting"; exit 0; }

[ -x "$BIN" ] || { log "missing binary $BIN"; exit 0; }

mkdir -p "$STATEDIR/config" "$STATEDIR/logs" "$STATEDIR/state" "$STATEDIR/run" 2>/dev/null
chmod 0700 "$STATEDIR" 2>/dev/null

# Trim old logs
for lf in "$LOG" "$WIFI_LOG"; do
  if [ -f "$lf" ]; then
    tail -c 131072 "$lf" > "$lf.tmp" 2>/dev/null && mv "$lf.tmp" "$lf" 2>/dev/null
  fi
done

# ---------------------------------------------------------------------------
# Wait for boot completion.
# ---------------------------------------------------------------------------
i=0
while [ "$i" -lt 60 ]; do
  case "$(getprop sys.boot_completed 2>/dev/null)" in
    1|true|TRUE) break ;;
  esac
  sleep 2
  i=$((i + 1))
done
[ "$i" -ge 60 ] && log "boot_completed never turned true within 120s; continuing anyway"

# ---------------------------------------------------------------------------
# WiFi auto-reconnect: make sure WiFi STA is on and connected to a saved
# network. Runs in background so it never blocks the daemon launch.
# ---------------------------------------------------------------------------
wifi_reconnect() {
  local attempt=0
  local max_attempts=90   # 90 × 4s = 6 minutes max
  local iface="wlan0"

  # Ensure WiFi is enabled (best-effort, may already be on)
  if command -v cmd >/dev/null 2>&1; then
    cmd wifi set-wifi-enabled enabled 2>/dev/null
  elif command -v svc >/dev/null 2>&1; then
    svc wifi enable 2>/dev/null
  fi

  wlog "starting WiFi reconnect loop (max ${max_attempts} attempts)"

  while [ "$attempt" -lt "$max_attempts" ]; do
    # Check if wlan0 has a usable IPv4 address (not just link-local)
    local ip
    ip=$(ip -4 addr show "$iface" 2>/dev/null | grep 'inet ' | grep -v '169.254' | head -1 | awk '{print $2}')
    if [ -n "$ip" ]; then
      wlog "connected: $iface has $ip (attempt $attempt)"
      return 0
    fi

    # Try to trigger a scan so saved networks re-associate faster
    if command -v cmd >/dev/null 2>&1; then
      cmd wifi start-scan 2>/dev/null
    fi

    # Toggle WiFi off/on once after a few failures to force re-association
    if [ "$attempt" -eq 12 ] || [ "$attempt" -eq 36 ]; then
      wlog "attempt $attempt: cycling WiFi to force re-association"
      if command -v cmd >/dev/null 2>&1; then
        cmd wifi set-wifi-enabled disabled 2>/dev/null
        sleep 3
        cmd wifi set-wifi-enabled enabled 2>/dev/null
      elif command -v svc >/dev/null 2>&1; then
        svc wifi disable 2>/dev/null
        sleep 3
        svc wifi enable 2>/dev/null
      fi
    fi

    attempt=$((attempt + 1))
    sleep 4
  done

  wlog "gave up after $max_attempts attempts — yorud will run without upstream WiFi"
  return 1
}

# Launch WiFi reconnect in background — non-blocking.
wifi_reconnect &
WIFI_PID=$!
log "WiFi reconnect background pid=$WIFI_PID"

# ---------------------------------------------------------------------------
# Single-instance check, then launch the supervisor detached.
# ---------------------------------------------------------------------------
if [ -f "$SUP_PID" ]; then
  OLD=$(sed 's/[^0-9].*//' "$SUP_PID" 2>/dev/null)
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    # Verify the process is actually yorud, not a recycled PID
    CMDLINE=$(cat "/proc/$OLD/cmdline" 2>/dev/null | tr '\0' ' ')
    case "$CMDLINE" in
      *yorud*) log "supervisor already running (pid $OLD)"; exit 0 ;;
      *) log "stale PID $OLD is not yorud ($CMDLINE), relaunching" ;;
    esac
  fi
fi

export YORU_STATE_DIR="$STATEDIR"
export YORU_MODPATH="$MODDIR"

OUT="$STATEDIR/logs/supervise.out"
if [ -f "$OUT" ]; then
  tail -c 262144 "$OUT" > "$OUT.tmp" 2>/dev/null && mv "$OUT.tmp" "$OUT" 2>/dev/null
fi

if command -v setsid >/dev/null 2>&1; then
  setsid "$BIN" supervise --state "$STATEDIR" >> "$OUT" 2>&1 < /dev/null &
  SUP=$!
else
  ( "$BIN" supervise --state "$STATEDIR" >> "$OUT" 2>&1 < /dev/null & )
  sleep 1
  SUP=$(ps -A -o PID,ARGS 2>/dev/null | grep "supervise" | grep yorud | grep -v grep | sed -n '1s/^ *//p' | cut -d' ' -f1)
  [ -z "$SUP" ] && SUP=$!
fi
echo "$SUP" > "$SUP_PID" 2>/dev/null
chmod 0600 "$SUP_PID" 2>/dev/null
log "supervisor launched pid=$SUP"

exit 0
