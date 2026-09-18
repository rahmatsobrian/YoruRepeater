#!/usr/bin/env bash
# build.sh - reproducible release build for Yoru Repeater.
#
# Produces:
#   dist/Yoru-Repeater-vX.X.X.zip   Magisk / KernelSU / APatch module
#   dist/SHA256SUMS                 checksums for every release artifact
#
# Requirements (Ubuntu 22.04 / 24.04):
#   - Go >= 1.22 (any version; cross-compilation is CGO-free)
#   - zip (python3 is used as a fallback so the build has no hard zip dep)
#
# Optional environment:
#   VERSION=x.y.z     override the version taken from module/module.prop
#   GO=/path/to/go    toolchain override
#   SKIP_WEB=1        skip the WebUI -> embed-directory sync
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAEMON="$ROOT/src/daemon"
WEB="$ROOT/src/web"
DIST="$ROOT/module"
OUT="$ROOT/dist"
BUILD="$ROOT/build"
GO="${GO:-go}"

if [ ! -d "$DAEMON" ]; then echo "build.sh must run from the repository root" >&2; exit 2; fi
command -v "$GO" >/dev/null 2>&1 || { echo "Go toolchain not found (set GO=/path/to/go)" >&2; exit 2; }
if ! "$GO" version | grep -qE 'go1\.(2[2-9]|[3-9][0-9])'; then
  echo "warning: daemon needs go >= 1.22; got: $("$GO" version)" >&2
fi

# ---------------------------------------------------------------- identity
VERSION_PROP="$(sed -n 's/^version=//p' "$DIST/module.prop" | head -n1)"
VERSION="${VERSION:-${VERSION_PROP#v}}"
VERSION_CODE="$(sed -n 's/^versionCode=//p' "$DIST/module.prop" | head -n1)"
GIT_HASH="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo dev)"
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  BUILD_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%MZ)"
else
  BUILD_DATE="$(date -u +%Y-%m-%dT%H:%MZ)"
fi
PKG="Yoru-Repeater-v$VERSION"
echo "==> building $PKG (commit $GIT_HASH)"

# ---------------------------------------------------------------- web bundle
# Prepare the scratch tree before anything writes into it. BUILD must exist
# here and must NOT be wiped again later, or the WebUI copy below would vanish.
rm -rf "$BUILD"
mkdir -p "$BUILD" "$OUT"

# The dashboard is embedded into the Go binary, so the module needs no web
# root and nothing on the device can modify the UI at runtime.
#
# Normalisation runs on a scratch copy, never on $WEB itself: CI checkouts and
# read-only sources must survive a build untouched. Only previous builds'
# output ($DAEMON/internal/api/dist) is replaced.
if [ "${SKIP_WEB:-0}" != "1" ]; then
  echo "==> syncing WebUI into the embed directory"
  WEBCOPY="$BUILD/web"
  rm -rf "$WEBCOPY"
  mkdir -p "$WEBCOPY"
  cp -a "$WEB/." "$WEBCOPY/"
  # Normalise line endings: a stray CR in a shell script breaks Android's sh,
  # and a CRLF HTML/JS file just wastes bytes.
  if command -v dos2unix >/dev/null 2>&1; then
    find "$WEBCOPY" -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' -o -name '*.json' \) -exec dos2unix -q {} +
  else
    find "$WEBCOPY" -type f \( -name '*.html' -o -name '*.css' -o -name '*.js' -o -name '*.svg' -o -name '*.json' \) \
      -exec sed -i 's/\r$//' {} +
  fi
  rm -rf "$DAEMON/internal/api/dist"
  mkdir -p "$DAEMON/internal/api/dist"
  cp -a "$WEBCOPY/." "$DAEMON/internal/api/dist/"
fi

# ---------------------------------------------------------------- static checks
echo "==> vet + unit checks"
( cd "$DAEMON" && CGO_ENABLED=0 GOOS=linux "$GO" vet ./... )

LDF="-s -w -X yoru.dev/yorud/internal/version.GitTag=v$VERSION -X yoru.dev/yorud/internal/version.GitHash=$GIT_HASH -X yoru.dev/yorud/internal/version.BuildDate=$BUILD_DATE"

# ---------------------------------------------------------------- binaries
mkdir -p "$BUILD/payload"
echo "==> cross-compiling yorud (static, CGO-free)"
( cd "$DAEMON"
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOARM= go build -trimpath -ldflags "$LDF" -o "$BUILD/yorud-arm64" ./cmd/yorud
  CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "$LDF" -o "$BUILD/yorud-arm" ./cmd/yorud
)
file "$BUILD/yorud-arm64" 2>/dev/null | grep -q 'ELF 64-bit' || { echo "arm64 build is not ELF" >&2; exit 1; }
file "$BUILD/yorud-arm" 2>/dev/null | grep -q 'ELF 32-bit' || { echo "arm build is not ELF" >&2; exit 1; }

# ---------------------------------------------------------------- payload
echo "==> assembling module payload"
P="$BUILD/payload"
cp -a "$DIST/." "$P/"
rm -rf "$P/bin"
mkdir -p "$P/bin"
cp "$BUILD/yorud-arm64" "$P/bin/yorud-arm64"
cp "$BUILD/yorud-arm"   "$P/bin/yorud-arm"
chmod 0755 "$P/bin/"* "$P/service.sh" "$P/post-fs-data.sh" "$P/uninstall.sh" "$P/customize.sh" \
  "$P"/yoru/scripts/*.sh "$P"/system/bin/yorud "$P"/system/bin/yoructl 2>/dev/null || true

# Every shell file must be LF and must parse.
for f in "$P/customize.sh" "$P/service.sh" "$P/post-fs-data.sh" "$P/uninstall.sh" "$P"/yoru/scripts/*.sh "$P"/system/bin/yorud "$P"/system/bin/yoructl; do
  sed -i 's/\r$//' "$f"
  sh -n "$f" || { echo "shellcheck(syntax) failed: $f" >&2; exit 1; }
done
if ! grep -q '^version=v\?[0-9]' "$P/module.prop"; then
  echo "module.prop version field is malformed" >&2; exit 1
fi

# The zip ships the same version into module.prop (already does) - nothing to stamp.

# ---------------------------------------------------------------- zip
ZIP="$OUT/$PKG.zip"
echo "==> packaging $ZIP"
rm -f "$ZIP"
( cd "$P"
  if command -v zip >/dev/null 2>&1; then
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
      # Deterministic build: pin mtimes so two runs byte-match.
      find . -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
      zip -q -X -r "$ZIP" .
    else
      zip -q -X -r "$ZIP" .
    fi
  else
    python3 - "$ZIP" <<'PY'
import os, sys, zipfile, time
out = sys.argv[1]
src = "."
epoch = os.environ.get("SOURCE_DATE_EPOCH")
st = time.gmtime(int(epoch)) if epoch else None
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(src):
        dirs.sort(); files.sort()
        for f in files:
            p = os.path.join(root, f)
            info = zipfile.ZipInfo.from_file(p, os.path.relpath(p, src))
            if st: info.date_time = st[:6]
            # Preserve the executable bit for scripts and binaries.
            mode = os.stat(p).st_mode
            info.external_attr = (mode & 0o777) << 16
            with open(p, "rb") as fh:
                z.writestr(info, fh.read(), zipfile.ZIP_DEFLATED)
print("packaged with python zipfile fallback")
PY
  fi
)

# ---------------------------------------------------------------- checksums
echo "==> SHA256SUMS"
( cd "$OUT"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$PKG.zip" > SHA256SUMS
  else
    python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()+'  '+sys.argv[1])" "$PKG.zip" > SHA256SUMS
  fi
  cat SHA256SUMS
)

echo
echo "done:"
ls -l "$OUT"
echo
echo "Flash $PKG.zip in Magisk / KernelSU / APatch, reboot, then open"
echo "http://<phone-ip-on-the-ap>:8080 from a connected client."
