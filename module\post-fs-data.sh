#!/system/bin/sh
# Yoru Repeater - post-fs-data.sh
# Runs in the post-fs-data stage (very early boot, before any services).
# Its only job is to prepare private state directories with correct modes and
# labels. It must never touch the network stack, start processes, or block:
# everything here has to finish in milliseconds to avoid delaying boot.
#
# shellcheck shell=sh disable=SC2034

MODDIR=${0%/*}
STATEDIR=/data/adb/yoru-repeater

# Create the state tree. 0700 root:root because config.json can contain a
# Wi-Fi passphrase and the dashboard password hash.
for d in "$STATEDIR" "$STATEDIR/config" "$STATEDIR/logs" "$STATEDIR/state" "$STATEDIR/run"; do
  [ -d "$d" ] || mkdir -p "$d" 2>/dev/null
  chmod 0700 "$d" 2>/dev/null
  chown 0 0 "$d" 2>/dev/null
done

# SELinux labeling: best effort. magisk/ksu domains already reach these paths;
# restorecon keeps things tidy where a context exists.
if [ -x /system/bin/restorecon ]; then
  /system/bin/restorecon -R "$STATEDIR" 2>/dev/null
fi
chcon -R u:object:system_file:s0 "$STATEDIR" 2>/dev/null

# Record the boot ID this install saw, used by diagnostics to answer
# "did the module run during this boot?" without parsing logs.
if [ -r /proc/sys/kernel/random/boot_id ]; then
  echo "$(cat /proc/sys/kernel/random/boot_id) $(date +%s)" > "$STATEDIR/state/last-boot" 2>/dev/null
  chmod 0600 "$STATEDIR/state/last-boot" 2>/dev/null
fi

exit 0
