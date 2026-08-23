#!/bin/sh
# Cross-compile libvpncloud.so into android/app/src/main/jniLibs.
# Requires: rustup target, Android NDK, cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi
#   cargo install cargo-ndk
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/android/app/src/main/jniLibs"
cd "$ROOT"
cargo ndk -t arm64-v8a -t armeabi-v7a -o "$OUT" build --release --lib
echo "Native libraries written to $OUT"
