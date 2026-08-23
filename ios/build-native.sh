#!/bin/sh
# Cross-compile libvpncloud.a into ios/libvpncloud.xcframework.
# Requires: rustup, Xcode command-line tools
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

DEVICE_TARGET=aarch64-apple-ios
SIM_TARGET=aarch64-apple-ios-sim

rustup target add "$DEVICE_TARGET" "$SIM_TARGET"

# Network Extension links a static library. Skip the interactive wizard (no TTY).
cargo build --release --lib --target "$DEVICE_TARGET" --no-default-features --features nat,websocket
cargo build --release --lib --target "$SIM_TARGET" --no-default-features --features nat,websocket

OUT="$ROOT/ios/libvpncloud.xcframework"
rm -rf "$OUT"

write_slice() {
  ident="$1"
  lib="$2"
  mkdir -p "$OUT/$ident/Headers"
  cp "$lib" "$OUT/$ident/libvpncloud.a"
  cp "$ROOT/ios/include/"*.h "$OUT/$ident/Headers/"
}

if xcodebuild -create-xcframework \
  -library "$ROOT/target/$DEVICE_TARGET/release/libvpncloud.a" \
  -headers "$ROOT/ios/include" \
  -library "$ROOT/target/$SIM_TARGET/release/libvpncloud.a" \
  -headers "$ROOT/ios/include" \
  -output "$OUT"
then
  :
else
  echo "xcodebuild -create-xcframework failed; assembling XCFramework layout by hand" >&2
  write_slice ios-arm64 "$ROOT/target/$DEVICE_TARGET/release/libvpncloud.a"
  write_slice ios-arm64-simulator "$ROOT/target/$SIM_TARGET/release/libvpncloud.a"
  cat > "$OUT/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AvailableLibraries</key>
	<array>
		<dict>
			<key>LibraryIdentifier</key>
			<string>ios-arm64</string>
			<key>LibraryPath</key>
			<string>libvpncloud.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
		</dict>
		<dict>
			<key>LibraryIdentifier</key>
			<string>ios-arm64-simulator</string>
			<key>LibraryPath</key>
			<string>libvpncloud.a</string>
			<key>HeadersPath</key>
			<string>Headers</string>
			<key>SupportedArchitectures</key>
			<array>
				<string>arm64</string>
			</array>
			<key>SupportedPlatform</key>
			<string>ios</string>
			<key>SupportedPlatformVariant</key>
			<string>simulator</string>
		</dict>
	</array>
	<key>CFBundlePackageType</key>
	<string>XFWK</string>
	<key>XCFrameworkFormatVersion</key>
	<string>1.0</string>
</dict>
</plist>
EOF
fi
echo "Native library written to $OUT"
