#!/bin/sh
# Build a macOS .pkg containing the CLI, GUI and a component script that
# installs the LaunchDaemon + menu bar agent (done by `vpncloud install`).
#
# Requires: Rust with both apple targets, pkgbuild. For a signed/notarized
# installer set SIGN_IDENTITY and optionally NOTARY_PROFILE (needs Xcode tools).
#
#   ./contrib/macos/package.sh [version]
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

VERSION=${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -1)}
DIST="$ROOT/dist/macos"
STAGE="$DIST/stage"
rm -rf "$DIST"
mkdir -p "$STAGE/usr/local/bin" "$STAGE/share/vpncloud"

for TARGET in x86_64-apple-darwin aarch64-apple-darwin; do
  echo "Building $TARGET ..."
  cargo build --release --target "$TARGET" --features installer,gui
done

for tool in vpncloud vpncloud-gui; do
  lipo -create \
    "$ROOT/target/x86_64-apple-darwin/release/$tool" \
    "$ROOT/target/aarch64-apple-darwin/release/$tool" \
    -output "$STAGE/usr/local/bin/$tool"
  chmod 755 "$STAGE/usr/local/bin/$tool"
done

cp README.md LICENSE.md "$STAGE/share/vpncloud/"
cp docs/TROUBLESHOOTING.md docs/SECURITY.md "$STAGE/share/vpncloud/"

# Post-install runs the CLI installer to register the daemon and tray agent.
SCRIPTS="$DIST/scripts"
mkdir -p "$SCRIPTS"
cat > "$SCRIPTS/postinstall" <<'EOF'
#!/bin/sh
set -e
/usr/local/bin/vpncloud install --service --tray >/dev/null 2>&1 || true
EOF
chmod 755 "$SCRIPTS/postinstall"
cat > "$SCRIPTS/preuninstall" <<'EOF'
#!/bin/sh
set -e
/usr/local/bin/vpncloud install --uninstall >/dev/null 2>&1 || true
EOF
chmod 755 "$SCRIPTS/preuninstall"

PKG="$DIST/vpncloud-$VERSION-universal.pkg"
if [ -n "${SIGN_IDENTITY:-}" ]; then
  pkgbuild --root "$STAGE" --identifier ca.witherow.vpncloud \
    --version "$VERSION" --install-location / \
    --scripts "$SCRIPTS" --sign "$SIGN_IDENTITY" "$PKG"
  echo "Signed package: $PKG"
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
    echo "Notarized: $PKG"
  fi
else
  pkgbuild --root "$STAGE" --identifier ca.witherow.vpncloud \
    --version "$VERSION" --install-location / \
    --scripts "$SCRIPTS" "$PKG"
  echo "Unsigned package: $PKG (set SIGN_IDENTITY / NOTARY_PROFILE to sign)"
fi
shasum -a 256 "$PKG" > "$PKG.sha256"

# Also produce a .dmg containing the installer package, for users who prefer
# a disk image. hdiutil ships with macOS.
if command -v hdiutil >/dev/null 2>&1; then
  DMG_STAGE="$DIST/dmg-stage"
  rm -rf "$DMG_STAGE"
  mkdir -p "$DMG_STAGE"
  cp "$PKG" "$DMG_STAGE/"
  cat > "$DMG_STAGE/README.txt" <<EOF
VpnCloud $VERSION for macOS (universal: x86_64 + arm64)

Double-click the .pkg to install the CLI, GUI, LaunchDaemon and menu bar tray.
After installing, edit /usr/local/etc/vpncloud/vpncloud.yaml and start with:
  sudo launchctl start system/ca.witherow.vpncloud

Uninstall with: sudo /usr/local/bin/vpncloud install --uninstall
Documentation: /usr/local/share/vpncloud/
EOF
  DMG="$DIST/vpncloud-$VERSION-universal.dmg"
  hdiutil create -volname "VpnCloud $VERSION" -srcfolder "$DMG_STAGE" \
    -ov -format UDZO "$DMG" >/dev/null
  shasum -a 256 "$DMG" > "$DMG.sha256"
  echo "Disk image: $DMG"
else
  echo "hdiutil not available; skipping .dmg (macOS only)"
fi
