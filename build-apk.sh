#!/usr/bin/env bash
# Builds LKMDet.apk without gradle: NDK lib -> javac -> d8 -> aapt2 -> package -> zipalign -> apksigner
set -e
cd "$(dirname "$0")"

SDK=/opt/android-sdk
AJAR="$SDK/platforms/android-37.0/android.jar"
BT="$SDK/build-tools/37.0.0"
NDKCC=$(ls /opt/android-ndk/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang | head -1)

echo "[1/7] NDK: liblkmdet.so"
"$NDKCC" -O2 -Wall -Wextra -pthread -shared -fPIC -DLKMDET_LIBRARY \
    -o jniLibs/arm64-v8a/liblkmdet.so lkmdet.c

echo "[2/7] keystore"
if [ ! -f lkmdet.keystore ]; then
    keytool -genkeypair -keystore lkmdet.keystore \
        -storepass android -keypass android -alias lkmdet \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=LKMDet, O=WildKernels" >/dev/null 2>&1
fi

echo "[3/7] javac"
mkdir -p build/obj build/stage/lib/arm64-v8a
javac --release 8 -classpath "$AJAR" -d build/obj \
    app/src/com/wildkernels/lkmdetector/MainActivity.java

echo "[4/7] d8"
"$BT/d8" --release --lib "$AJAR" --min-api 26 --output build/obj \
    $(find build/obj -name '*.class')

echo "[5/7] aapt2 link"
"$BT/aapt2" link --manifest app/AndroidManifest.xml -I "$AJAR" \
    -o build/unsigned.apk

echo "[6/7] package classes.dex + lib"
cp jniLibs/arm64-v8a/liblkmdet.so build/stage/lib/arm64-v8a/
cp build/obj/classes.dex build/stage/
( cd build/stage && jar -uf ../unsigned.apk classes.dex lib/arm64-v8a/liblkmdet.so )

echo "[7/7] zipalign + sign"
"$BT/zipalign" -f 4 build/unsigned.apk build/aligned.apk
"$BT/apksigner" sign --ks lkmdet.keystore --ks-pass pass:android \
    --key-pass pass:android --out LKMDet.apk build/aligned.apk
"$BT/apksigner" verify --print-certs LKMDet.apk
echo
ls -la LKMDet.apk
