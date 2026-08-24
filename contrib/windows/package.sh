#!/bin/sh
# Build Windows setup.exe + portable zip for one or both architectures.
# Requires: makensis (NSIS 3), curl, unzip, existing dist/vpncloud-*-windows-*.exe
#
#   ./contrib/windows/package.sh              # both x86_64 and aarch64
#   ./contrib/windows/package.sh x86_64
#   ./contrib/windows/package.sh aarch64
#
# Bundles the official Wintun 0.14.1 DLL (TUN). TAP (tap-windows6) is not
# shipped: the NSIS setup can download OpenVPN's signed installer at
# install time (optional, unchecked).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)
WINTUN_VER=0.14.1
WINTUN_SHA=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VER}.zip"
CACHE="$ROOT/builder/cache"
ZIP="$CACHE/wintun-${WINTUN_VER}.zip"

if ! command -v makensis >/dev/null 2>&1; then
  echo "makensis not found. Install NSIS (e.g. brew install makensis / nsis)." >&2
  exit 1
fi

mkdir -p "$CACHE" dist
if [ ! -f "$ZIP" ]; then
  curl -fsSL -o "$ZIP" "$WINTUN_URL"
fi
got=$(shasum -a 256 "$ZIP" | awk '{print $1}')
if [ "$got" != "$WINTUN_SHA" ]; then
  echo "Wintun zip checksum mismatch: $got (expected $WINTUN_SHA)" >&2
  exit 1
fi
rm -rf "$CACHE/wintun"
unzip -q -o "$ZIP" -d "$CACHE"

write_readme() {
  stage=$1
  cat > "$stage/README.txt" <<EOF
VpnCloud ${VERSION} for Windows
==============================

This folder contains:

  vpncloud.exe       CLI (build with --features installer)
  vpncloud-gui.exe   Desktop GUI
  wintun.dll         Official Wintun ${WINTUN_VER} (TUN / layer-3)
  example.net.disabled
  LICENSE.md         VpnCloud (GPL-3.0)
  WINTUN-LICENSE.txt Wintun prebuilt-DLL license (WireGuard LLC)

TUN is the default device type. Creating the adapter needs Administrator.

  vpncloud.exe --type tun --ip 10.0.0.2/24 -c HOST:3210 -p PASS

Or use the GUI. Keep wintun.dll next to vpncloud.exe.

TAP (layer-2) is optional and is NOT shipped. The setup.exe can download
OpenVPN's tap-windows6 installer (9.24.7-I601, SHA-256 verified) when you
tick "TAP driver". Or install tap-windows6 yourself (hardware id tap0901),
then:

  vpncloud.exe --type tap --ip 10.0.0.2/24 -c HOST:3210 -p PASS

Optional Windows service (Administrator; edit the yaml first):

  vpncloud.exe service install --config C:\\ProgramData\\VpnCloud\\vpncloud.yaml

Do not start the service until crypto.password / peers / ip are set.
EOF
}

package_one() {
  arch=$1
  wintun_bin=$2
  cli="dist/vpncloud-${VERSION}-windows-${arch}.exe"
  gui="dist/vpncloud-gui-${VERSION}-windows-${arch}.exe"
  if [ ! -f "$cli" ] || [ ! -f "$gui" ]; then
    echo "Missing $cli or $gui — build those first." >&2
    exit 1
  fi
  dll="$CACHE/wintun/bin/${wintun_bin}/wintun.dll"
  if [ ! -f "$dll" ]; then
    echo "Missing $dll" >&2
    exit 1
  fi

  stage="$ROOT/dist/windows-stage-${arch}"
  rm -rf "$stage"
  mkdir -p "$stage"
  cp "$cli" "$stage/vpncloud.exe"
  cp "$gui" "$stage/vpncloud-gui.exe"
  cp "$dll" "$stage/wintun.dll"
  cp "$CACHE/wintun/LICENSE.txt" "$stage/WINTUN-LICENSE.txt"
  cp "$ROOT/LICENSE.md" "$stage/LICENSE.md"
  cp "$ROOT/assets/example.net.disabled" "$stage/example.net.disabled"
  write_readme "$stage"

  out="dist/vpncloud-${VERSION}-windows-${arch}-setup.exe"
  makensis -V2 \
    -DVERSION="$VERSION" \
    -DSTAGE="$stage" \
    -DOUTFILE="$ROOT/$out" \
    "$ROOT/contrib/windows/vpncloud.nsi"

  zip_path="dist/vpncloud-${VERSION}-windows-${arch}.zip"
  rm -f "$zip_path"
  (
    cd "$stage"
    zip -q -9 "$ROOT/$zip_path" \
      vpncloud.exe vpncloud-gui.exe wintun.dll \
      LICENSE.md WINTUN-LICENSE.txt README.txt example.net.disabled
  )
  echo "Wrote $out"
  echo "Wrote $zip_path"
}

ARCHS=${1:-}
if [ -z "$ARCHS" ]; then
  package_one x86_64 amd64
  package_one aarch64 arm64
else
  case "$ARCHS" in
    x86_64|amd64) package_one x86_64 amd64 ;;
    aarch64|arm64) package_one aarch64 arm64 ;;
    *) echo "usage: $0 [x86_64|aarch64]" >&2; exit 1 ;;
  esac
fi
