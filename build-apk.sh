#!/usr/bin/env bash
# Builds the three Wild Detector APKs without gradle:
#   WildDetector.apk (bear cards) / WildDetectorRev.apk (reveny) / WildDetectorX.apk (wild)
set -e
cd "$(dirname "$0")"

SDK="${SDK_ROOT:-/opt/android-sdk}"
AJAR=$(ls "$SDK"/platforms/android-*/android.jar | sort -V | tail -1)
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
NDK="${NDK_ROOT:-/opt/android-ndk}"
NDKCC=$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang | head -1)

echo "[1] NDK: liblkmdet.so (all three apps share it)"
mkdir -p jniLibs/arm64-v8a
"$NDKCC" -O2 -Wall -Wextra -pthread -shared -fPIC -DLKMDET_LIBRARY \
    -o jniLibs/arm64-v8a/liblkmdet.so lkmdet.c

echo "[2] keystore"
if [ ! -f lkmdet.keystore ]; then
    keytool -genkeypair -keystore lkmdet.keystore \
        -storepass android -keypass android -alias lkmdet \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=WildDetector, O=WildKernels" >/dev/null 2>&1
fi

build_one() { # $1 = java source, $2 = manifest, $3 = out apk
    local SRC="$1" MF="$2" OUT="$3"
    local TAG; TAG=$(basename "$OUT" .apk)
    mkdir -p "build/$TAG/obj" "build/$TAG/stage/lib/arm64-v8a"
    find "build/$TAG/obj" -name '*.class' -delete 2>/dev/null || true
    echo "[3] $TAG: javac"
    javac --release 8 -classpath "$AJAR" -d "build/$TAG/obj" "$SRC"
    echo "[4] $TAG: d8"
    "$BT/d8" --release --lib "$AJAR" --min-api 26 --output "build/$TAG/obj" \
        $(find "build/$TAG/obj" -name '*.class')
    echo "[5] $TAG: aapt2 link"
    "$BT/aapt2" link --manifest "$MF" -I "$AJAR" -o "build/$TAG/unsigned.apk"
    echo "[6] $TAG: package"
    cp jniLibs/arm64-v8a/liblkmdet.so "build/$TAG/stage/lib/arm64-v8a/"
    cp "build/$TAG/obj/classes.dex" "build/$TAG/stage/"
    ( cd "build/$TAG/stage" && jar -uf "../unsigned.apk" classes.dex lib/arm64-v8a/liblkmdet.so )
    echo "[7] $TAG: zipalign + sign"
    "$BT/zipalign" -f 4 "build/$TAG/unsigned.apk" "build/$TAG/aligned.apk"
    "$BT/apksigner" sign --ks lkmdet.keystore --ks-pass pass:android \
        --key-pass pass:android --out "$OUT" "build/$TAG/aligned.apk"
    "$BT/apksigner" verify --print-certs "$OUT" >/dev/null
    echo "built $OUT"
}

build_one app/src/com/wildkernels/lkmdetector/MainActivity.java  app/AndroidManifest.xml  WildDetector.apk
build_one app2/src/com/wildkernels/wilddetector/rev/MainActivity.java app2/AndroidManifest.xml WildDetectorRev.apk
build_one app3/src/com/wildkernels/wilddetector/x/MainActivity.java   app3/AndroidManifest.xml WildDetectorX.apk
echo
ls -la WildDetector*.apk
