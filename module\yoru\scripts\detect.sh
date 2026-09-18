#!/system/bin/sh
# Yoru Repeater - detect.sh
# Environment detection dump, POSIX sh, zero dependencies. It answers the
# question "what does this device actually have?" without assuming anything:
# missing tools are reported as missing, never guessed.
#
# Used by the installer banner, diagnostics.sh and as the offline fallback
# for `yorud diagnose` when the daemon is not running.
#
# shellcheck shell=sh disable=SC2034

out() { printf '%s\n' "$1"; }
kv() { printf '%-22s %s\n' "$1" "$2"; }

prop() {
  v=$(getprop "$1" 2>/dev/null)
  [ -n "$v" ] && out "$v" || out ""
}

tool() {
  if command -v "$1" >/dev/null 2>&1; then
    kv "$1" "yes"
  else
    kv "$1" "no"
  fi
}

out "== Yoru Repeater environment detection =="
out ""

ANDROID=$(prop ro.build.version.release)
SDK=$(prop ro.build.version.sdk)
FINGERPRINT=$(prop ro.build.fingerprint)
out "android_version    ${ANDROID:-unknown}"
out "sdk                ${SDK:-unknown}"
out "fingerprint        ${FINGERPRINT:-unknown}"
out "abi                $(prop ro.product.cpu.abi)"
out "abilist            $(prop ro.product.cpu.abilist)"
out "board              $(prop ro.product.board)"
out "hardware           $(prop ro.hardware)"
out "boot_hardware      $(prop ro.boot.hardware)"
out "soc                $(prop ro.soc.model)"
out "model              $(prop ro.product.model)"
out "kernel             $(uname -r 2>/dev/null)"
out "machine            $(uname -m 2>/dev/null)"
out ""

# root manager ---------------------------------------------------------------
ROOT=unknown
[ -n "$KSU" ] && ROOT="KernelSU ($KSU)"
[ -n "$APATCH" ] && ROOT="APatch ($APATCH)"
[ -n "$MAGISK_VER_CODE" ] && ROOT="Magisk ($MAGISK_VER_CODE)"
[ "$ROOT" = unknown ] && [ -d /sbin/.magisk ] && ROOT="Magisk (detected)"
out "root               $ROOT"
out "uid                $(id -u 2>/dev/null)"
out "selinux            $(getenforce 2>/dev/null || echo unknown)"
out ""

# network interfaces ----------------------------------------------------------
out "== interfaces =="
if command -v ip >/dev/null 2>&1; then
  ip -o link show 2>/dev/null | while IFS= read -r l; do out "  $l"; done
else
  for i in /sys/class/net/*; do
    [ -e "$i" ] || continue
    n=$(basename "$i")
    st=$(cat "$i/operstate" 2>/dev/null)
    mac=$(cat "$i/address" 2>/dev/null)
    out "  $n state=${st:-?} mac=${mac:-?}"
  done
fi
out ""

out "== routes (default) =="
if command -v ip >/dev/null 2>&1; then
  ip route show default 2>/dev/null | sed 's/^/  /'
fi
if command -v ip >/dev/null 2>&1; then
  ip -6 route show default 2>/dev/null | sed 's/^/  /'
fi
out ""

# wifi hardware ----------------------------------------------------------------
out "== 802.11 radios =="
found_phy=0
for phy in /sys/class/ieee80211/phy*; do
  [ -e "$phy" ] || continue
  found_phy=1
  name=$(basename "$phy" 2>/dev/null)
  drv=$(readlink "$phy/driver" 2>/dev/null | sed 's#.*/##')
  mac=$(cat "$phy/macaddress" 2>/dev/null)
  out "  $name driver=${drv:-unknown} mac=${mac:-unknown}"
  iff=$(ls "$phy/net" 2>/dev/null)
  [ -n "$iff" ] && out "    interfaces: $(echo "$iff" | tr '\n' ' ')"
done
[ "$found_phy" = 0 ] && out "  none exposed by this kernel"
out ""

out "== wifi tools =="
tool iw
tool iwconfig
tool wpa_cli
tool hostapd
out ""

out "== firewall / routing tools =="
tool iptables
tool ip6tables
tool nft
tool tc
tool ip
out ""

out "== dhcp / dns =="
tool dnsmasq
tool toybox
tool busybox
out ""

out "== android control =="
tool cmd
tool svc
tool settings
tool dumpsys
out ""

# power + thermal presence (counts only, detail lives in the daemon) -----------
out "== sensors =="
batts=""
for ps in /sys/class/power_supply/*; do
  [ -e "$ps" ] || continue
  t=$(cat "$ps/type" 2>/dev/null)
  batts="$batts $(basename "$ps")=$t"
done
out "  power_supply:$batts"
n=$(ls -d /sys/class/thermal/thermal_zone* 2>/dev/null | wc -l)
out "  thermal_zones: $n"
n=$(ls -d /sys/class/hwmon/hwmon* 2>/dev/null | wc -l)
out "  hwmon_devices: $n"
out ""

out "== done =="
