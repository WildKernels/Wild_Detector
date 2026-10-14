#!/usr/bin/env bash
# Builds LKMDet.apk without gradle: NDK lib -> javac -> d8 -> aapt2 -> package -> zipalign -> apksigner
set -e
cd "$(dirname "$0")"

# Paths: local defaults, CI overrides via SDK_ROOT / NDK_ROOT
SDK="${SDK_ROOT:-/opt/android-sdk}"
AJAR=$(ls "$SDK"/platforms/android-*/android.jar | sort -V | tail -1)
BT=$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)
NDK="${NDK_ROOT:-/opt/android-ndk}"
NDKCC=$(ls "$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android24-clang | head -1)

echo "[1/7] NDK: liblkmdet.so"
mkdir -p jniLibs/arm64-v8a
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
