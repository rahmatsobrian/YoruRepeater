#!/usr/bin/env bash
# test-install.sh - static validation of a release ZIP.
#
# Runs on a normal Linux box (Ubuntu 22.04/24.04), no device needed:
# it proves the artifact that users flash is structurally correct before
# anyone puts it on a phone.
#
# Usage: ./test-install.sh ../dist/Yoru-Repeater-v1.0.0.zip
set -uo pipefail

ZIP="${1:-}"
pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[1m\033[31mFAIL\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; fail=$((fail+1)); }
note() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

if [ -z "$ZIP" ] || [ ! -f "$ZIP" ]; then
  echo "usage: $0 <path-to-release.zip>" >&2
  exit 2
fi
command -v unzip >/dev/null 2>&1 || { echo "unzip is required" >&2; exit 2; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

note "zip integrity"
if unzip -tq "$ZIP" > "$TMP/testzip.log" 2>&1; then ok "zip central directory intact"; else bad "zip corrupt" "$(tail -3 "$TMP/testzip.log")"; fi
unzip -q "$ZIP" -d "$TMP/x" || { echo "cannot extract"; exit 1; }

note "mandatory module files"
for f in module.prop customize.sh service.sh post-fs-data.sh uninstall.sh; do
  if [ -f "$TMP/x/$f" ]; then ok "$f present"; else bad "$f missing"; fi
done
for f in yoru/scripts/detect.sh yoru/scripts/diagnostics.sh yoru/scripts/cleanup.sh system/bin/yorud system/bin/yoructl; do
  if [ -f "$TMP/x/$f" ]; then ok "$f present"; else bad "$f missing"; fi
done

note "module.prop fields"
if grep -q '^id=yoru-repeater$' "$TMP/x/module.prop"; then ok "id correct"; else bad "id field"; fi
for k in name version versionCode author description; do
  if grep -q "^$k=" "$TMP/x/module.prop"; then ok "$k present"; else bad "$k missing"; fi
done
VER=$(sed -n 's/^version=//p' "$TMP/x/module.prop")
case "$VER" in v[0-9]*) ok "version is tagged ($VER)";; *) bad "version format" "$VER";; esac

note "architecture payload"
for abi in arm64 arm; do
  f="$TMP/x/bin/yorud-$abi"
  if [ -f "$f" ]; then
    if command -v file >/dev/null 2>&1; then
      desc=$(file -b "$f")
      case "$abi" in
        arm64) echo "$desc" | grep -q 'ELF 64-bit.*ARM aarch64' && ok "yorud-arm64 is AArch64 ELF" || bad "yorud-arm64 format" "$desc" ;;
        arm)   echo "$desc" | grep -q 'ELF 32-bit.*ARM' && ok "yorud-arm is ARM32 ELF" || bad "yorud-arm format" "$desc" ;;
      esac
      echo "$desc" | grep -qi 'static' && ok "yorud-$abi statically linked (no bionic surprises)" || true
    else
      ok "yorud-$abi present (file(1) unavailable, format unchecked)"
    fi
  else
    bad "bin/yorud-$abi missing"
  fi
done

note "shell syntax (Android sh compatibility)"
for f in "$TMP/x/customize.sh" "$TMP/x/service.sh" "$TMP/x/post-fs-data.sh" "$TMP/x/uninstall.sh" "$TMP/x"/yoru/scripts/*.sh "$TMP/x"/system/bin/yorud "$TMP/x"/system/bin/yoructl; do
  [ -f "$f" ] || continue
  name="${f#$TMP/x/}"
  if grep -q $'\r' "$f"; then bad "CRLF line endings in $name"; continue; fi
  head -1 "$f" | grep -Eq '^#!/(system/bin/)?sh' && ok "$name has a plain-sh shebang" || bad "$name shebang" "$(head -1 "$f")"
  if sh -n "$f" 2>"$TMP/synerr"; then ok "$name parses"; else bad "$name syntax" "$(cat "$TMP/synerr")"; fi
done

note "embedded web assets sanity"
if [ -f "$TMP/x/service.sh" ]; then ok "service.sh present"; fi
# The dashboard is embedded inside the binary; assert it is in there and assert
# the bundle itself contains no external network references.
for bin in "$TMP/x"/bin/yorud-*; do
  [ -f "$bin" ] || continue
  if grep -aq 'api/v1/status' "$bin"; then ok "$(basename "$bin") embeds the API (dashboard compiled in)"; else bad "$(basename "$bin") seems to lack the embedded UI"; fi
  if grep -aqE '(fonts.googleapis|cdn\.jsdelivr|unpkg\.com)' "$bin"; then bad "$(basename "$bin") references an external CDN"; else ok "$(basename "$bin") has no CDN references"; fi
done

note "dangerous patterns must not exist"
# Master rules: no global rule flushes, no rm -rf outside Yoru paths.
if grep -aEn 'iptables(-\[6\])? +-F|iptables +-t +[a-z]+ +-F|nft +flush' "$TMP/x"/customize.sh "$TMP/x"/service.sh "$TMP/x"/post-fs-data.sh "$TMP/x"/uninstall.sh "$TMP/x"/yoru/scripts/*.sh 2>/dev/null; then
  bad "a global firewall flush was found (forbidden)"
else
  ok "no global firewall flush anywhere in the payload"
fi
if grep -aEn 'rm +-rf +/data\b|rm +-rf +/$|mkfs' "$TMP/x"/*.sh "$TMP/x"/yoru/scripts/*.sh 2>/dev/null; then
  bad "catastrophic rm/mkfs pattern found"
else
  ok "no catastrophic filesystem commands"
fi

printf '\n\033[1m================================\033[0m\n'
printf 'passed=%s failed=%s\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
