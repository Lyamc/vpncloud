#!/bin/sh
# Cross-compile libvpncloud.so into android/app/src/main/jniLibs.
# Requires: rustup target, Android NDK, cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi
#   cargo install cargo-ndk
set -e
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT="$ROOT/android/app/src/main/jniLibs"
cd "$ROOT"
# Skip wizard/dialoguer. Host crate-type is rlib; JNI needs a cdylib.
cargo ndk -t arm64-v8a -t armeabi-v7a -o "$OUT" rustc --release --lib \
  --no-default-features --features nat,websocket,noise \
  -- --crate-type cdylib
echo "Native libraries written to $OUT"
