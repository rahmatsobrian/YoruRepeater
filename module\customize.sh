#!/system/bin/sh
# Yoru Repeater - Magisk / KernelSU / APatch installer.
# Executed by the root installer (sh, POSIX). Must never assume busybox,
# iptables, iw, hostapd, dnsmasq or a specific interface exist.
#
# shellcheck shell=sh disable=SC2034,SC2015,SC2016,SC3051,SC3054

VERSION="v1.0.0"
VERSION_CODE=1
SCHEMA_VERSION=1
PORT_DEFAULT=8080

abort() {
  ui_print "! $1"
  ui_print "! Installation aborted."
  exit 1
}

# ---------------------------------------------------------------------------
# Info banner
# ---------------------------------------------------------------------------
ui_print " "
ui_print "  Yoru Repeater $VERSION ($VERSION_CODE)"
ui_print "  Root Wi-Fi repeater + real-time monitor"
ui_print " "

# ---------------------------------------------------------------------------
# Android release detection
# ---------------------------------------------------------------------------
SDK=$(getprop ro.build.version.sdk 2>/dev/null)
case "$SDK" in
  ''|*[!0-9]*) SDK=0 ;;
esac

RELEASE=$(getprop ro.build.version.release 2>/dev/null)
[ -z "$RELEASE" ] && RELEASE="unknown"

if [ "$SDK" -gt 0 ] && [ "$SDK" -lt 29 ]; then
  ui_print "! Android $RELEASE (SDK $SDK) is below Android 10 (SDK 29)."
  ui_print "! Yoru Repeater is designed and validated for Android 10+."
  abort "Unsupported Android version"
fi

ui_print "- Android $RELEASE (SDK ${SDK:-unknown})"

# ---------------------------------------------------------------------------
# ABI / architecture detection
# ---------------------------------------------------------------------------
detect_abi() {
  for p in ro.product.cpu.abi2 ro.product.cpu.abi ro.boot.product.hardware.sku; do
    v=$(getprop "$p" 2>/dev/null)
    case "$v" in
      *arm64*|*aarch64*) echo "arm64"; return 0 ;;
    esac
  done
  case "$(uname -m 2>/dev/null)" in
    aarch64|arm64) echo "arm64"; return 0 ;;
  esac
  for p in ro.product.cpu.abi ro.product.cpu.abilist ro.boot.product.hardware.sku; do
    v=$(getprop "$p" 2>/dev/null)
    case "$v" in
      *armeabi-v7a*|*armeabi*) echo "arm"; return 0 ;;
    esac
  done
  case "$(uname -m 2>/dev/null)" in
    armv7*|armv8*|arm) echo "arm"; return 0 ;;
  esac
  for p in ro.product.cpu.abilist ro.product.cpu.abilist64; do
    v=$(getprop "$p" 2>/dev/null)
    case "$v" in
      *arm64*|*aarch64*) echo "arm64"; return 0 ;;
    esac
  done
  echo ""
}

ABI=$(detect_abi)
if [ -z "$ABI" ]; then
  ui_print "! Unable to determine CPU architecture."
  ui_print "  Checked: ro.product.cpu.abi, ro.product.cpu.abilist, uname -m"
  abort "Unknown architecture"
fi
ui_print "- Architecture: $ABI ($(getprop ro.product.cpu.abi 2>/dev/null))"

if [ ! -f "$MODPATH/bin/yorud-$ABI" ]; then
  ui_print "! No $ABI binary is bundled in this module."
  ui_print "  Bundled: $(ls "$MODPATH/bin" 2>/dev/null | tr '\n' ' ')"
  abort "Unsupported architecture ($ABI)"
fi

# ---------------------------------------------------------------------------
# KernelSU / APatch / Magisk detection (informational only)
# ---------------------------------------------------------------------------
ROOT_IMPL="unknown"
if [ -n "$KSU" ]; then
  ROOT_IMPL="KernelSU"
elif [ -n "$APATCH" ]; then
  ROOT_IMPL="APatch"
elif [ -n "$MAGISK_VER_CODE" ]; then
  ROOT_IMPL="Magisk"
elif [ -d /sbin/.magisk ] || [ -L /data/adb/magisk ]; then
  ROOT_IMPL="Magisk (detected)"
fi
ui_print "- Root solution: $ROOT_IMPL"

BOARD=$(getprop ro.product.board 2>/dev/null)
HARDWARE=$(getprop ro.hardware 2>/dev/null)
BOOT_HW=$(getprop ro.boot.hardware 2>/dev/null)
[ -z "$BOARD" ] && BOARD=$(getprop ro.board.platform 2>/dev/null)
ui_print "- SoC/board: ${BOARD:-unknown} ${HARDWARE:-} ${BOOT_HW:-}"

# ---------------------------------------------------------------------------
# Optional tooling preview (never fatal)
# ---------------------------------------------------------------------------
preview_tool() {
  t="$1"
  if command -v "$t" >/dev/null 2>&1; then
    printf '%s ' "$t"
  fi
}
FOUND=""
for t in ip iw iwconfig iptables nft tc hostapd dnsmasq toybox busybox settings cmd svc; do
  FOUND="$FOUND$(preview_tool "$t")"
done
ui_print "- Shell tools present: ${FOUND:-none}"

WIFIDIR=$(ls -d /sys/class/ieee80211/phy* 2>/dev/null | head -n 1)
if [ -n "$WIFIDIR" ]; then
  ui_print "- 802.11 phy: $(basename "$WIFIDIR") driver: $(readlink -f "$WIFIDIR/driver" 2>/dev/null | sed 's#.*/##')"
else
  ui_print "! No ieee80211 phy found in /sys/class/ieee80211."
  ui_print "! Repeater/AP mode may be unavailable; Yoru will still install"
  ui_print "! and report exact reasons at runtime."
fi

# ---------------------------------------------------------------------------
# Payload layout
# ---------------------------------------------------------------------------
ui_print "- Installing files"

rm -rf "$MODPATH/yoru/bin" 2>/dev/null
mkdir -p "$MODPATH/yoru/bin"

cp -f "$MODPATH/bin/yorud-$ABI" "$MODPATH/yoru/bin/yorud"
chmod 0755 "$MODPATH/yoru/bin/yorud"
chcon u:object:system_file:s0 "$MODPATH/yoru/bin/yorud" 2>/dev/null

rm -rf "$MODPATH/bin"

# A private copy of the binary and the cleanup script lives in the state
# directory so uninstall (which runs after the module folder may already be
# unmounted) can still stop processes and scrub Yoru's firewall rules.
mkdir -p /data/adb/yoru-repeater/backup /data/adb/yoru-repeater/config \
         /data/adb/yoru-repeater/logs /data/adb/yoru-repeater/state \
         /data/adb/yoru-repeater/run 2>/dev/null
cp -f "$MODPATH/yoru/bin/yorud" /data/adb/yoru-repeater/backup/yorud 2>/dev/null
cp -f "$MODPATH/yoru/scripts/cleanup.sh" /data/adb/yoru-repeater/backup/cleanup.sh 2>/dev/null
chmod 0755 /data/adb/yoru-repeater/backup/yorud /data/adb/yoru-repeater/backup/cleanup.sh 2>/dev/null
chmod 0700 /data/adb/yoru-repeater /data/adb/yoru-repeater/config \
           /data/adb/yoru-repeater/state /data/adb/yoru-repeater/run 2>/dev/null

# SELinux contexts on the payload. Best effort: some kernels refuse chcon on
# /data with certain policies - that is not fatal because Yoru runs from the
# root daemon domain (magisk/kernel/su) which is already unconfined.
if [ -d "$MODPATH" ]; then
  chcon -R u:object:system_file:s0 "$MODPATH/yoru" 2>/dev/null
  chcon u:object:system_file:s0 "$MODPATH/service.sh" 2>/dev/null
  chcon u:object:system_file:s0 "$MODPATH/post-fs-data.sh" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# Previous install / config hand-off
# Config lives in /data/adb/yoru-repeater/config and is deliberately NOT
# touched here, so an upgrade keeps user settings.
# ---------------------------------------------------------------------------
if [ -d /data/adb/yoru-repeater ]; then
  ui_print "- Existing configuration found (kept)"
fi

# ---------------------------------------------------------------------------
# Boot script sanity check: refuse to install a service.sh that cannot run,
# otherwise a broken module could delay boot.
# ---------------------------------------------------------------------------
if [ ! -s "$MODPATH/service.sh" ]; then
  abort "service.sh missing from payload"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644 2>/dev/null
[ -x "$MODPATH/yoru/bin/yorud" ] || chmod 0755 "$MODPATH/yoru/bin/yorud"
[ -f "$MODPATH/service.sh" ] && chmod 0755 "$MODPATH/service.sh"
[ -f "$MODPATH/post-fs-data.sh" ] && chmod 0755 "$MODPATH/post-fs-data.sh"
[ -f "$MODPATH/uninstall.sh" ] && chmod 0755 "$MODPATH/uninstall.sh"
[ -f "$MODPATH/yoru/scripts/detect.sh" ] && chmod 0755 "$MODPATH/yoru/scripts/detect.sh"
[ -f "$MODPATH/yoru/scripts/diagnostics.sh" ] && chmod 0755 "$MODPATH/yoru/scripts/diagnostics.sh"
[ -f "$MODPATH/yoru/scripts/cleanup.sh" ] && chmod 0755 "$MODPATH/yoru/scripts/cleanup.sh"
[ -f "$MODPATH/system/bin/yorud" ] && chmod 0755 "$MODPATH/system/bin/yorud"
[ -f "$MODPATH/system/bin/yoructl" ] && chmod 0755 "$MODPATH/system/bin/yoructl"

ui_print " "
ui_print "  Installed Yoru Repeater $VERSION"
ui_print "  ABI=$ABI  root=$ROOT_IMPL  SDK=${SDK:-?}"
ui_print "  Dashboard (once started): http://<ap-ip>:$PORT_DEFAULT"
ui_print "  Control CLI: yoructl status"
ui_print " "
