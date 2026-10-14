#!/usr/bin/env bash
# Build lkmdet for arm64 Android with the NDK clang.
set -euo pipefail
cd "$(dirname "$0")"

NDK="${NDK_ROOT:-${NDK:-/opt/android-ndk}}"
CC="$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang 2>/dev/null | head -n1 || true)"
if [ ! -x "$CC" ]; then
	echo "NDK aarch64 clang not found under $NDK" >&2
	exit 1
fi
echo "CC: $CC"
"$CC" -O2 -Wall -Wextra -pthread -o lkmdet lkmdet.c
ls -l lkmdet
echo "deploy: adb push lkmdet /data/local/tmp/ && adb shell /data/local/tmp/lkmdet"
