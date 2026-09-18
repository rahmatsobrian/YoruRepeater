#!/usr/bin/env bash
# Parse-check every shell file with the interpreter its shebang names.
#
#   #!/system/bin/sh  -> dash, plus busybox ash when available. Android sh is
#                        not bash, so anything shipped under module/ must be
#                        POSIX-clean.
#   #!/bin/bash       -> bash
#
# This is the local equivalent of CI's "shell syntax" step, so a broken script
# is caught before a push rather than five minutes into a workflow run.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

fail=0
checked=0

# check <label> <file> <cmd...> - run `cmd -n file`; report a failure once.
# The trailing `$f` is appended here so callers pass a bare interpreter name
# ("dash") or an applet form ("busybox ash") without special-casing.
check() {
  local label="$1" f="$2"
  shift 2
  # Guard against a silently-wrong invocation: if the interpreter does not
  # support -n it may exit 0 having done nothing, which would look like a pass.
  if ! "$@" -n /dev/null; then
    echo "SKIP ($label) $f: interpreter does not support -n"
    return 0
  fi
  checked=$((checked + 1))
  if ! "$@" -n "$f" 2>/tmp/lintsh.err; then
    echo "FAIL ($label) $f"
    sed 's/^/      /' /tmp/lintsh.err
    fail=1
  fi
}

# Files under module/ without a .sh suffix (system/bin wrappers) are Android sh.
while IFS= read -r f; do
  shebang=$(head -n 1 "$f" 2>/dev/null)
  case "$shebang" in
    *bash*)
      check bash "$f" bash
      ;;
    *)
      # Android's /system/bin/sh is close to dash/ash; require POSIX.
      check dash "$f" dash
      if command -v busybox >/dev/null 2>&1; then
        # busybox has no -n of its own; the syntax check lives in the ash applet.
        check busybox-ash "$f" busybox ash
      fi
      ;;
  esac
done < <(find . -type f \
              \( -name '*.sh' -o -path './module/system/bin/*' -o -path './module/yoru/bin/*' \) \
              -not -path './.git/*' \
              -not -path './src/daemon/internal/api/dist/*' \
              -not -name 'lint-sh.sh' 2>/dev/null)

if [ "$fail" -eq 0 ]; then
  echo "OK   $checked shell checks passed"
fi
exit "$fail"
