#!/usr/bin/env bash
# Builds liboqs (static, ML-DSA-65 only) and the JNI bridge for THIS machine, for JVM tests. Output: third_party/jni-host/libnocoqs.so
set -e
cd "$(dirname "$0")/.."
bash tools/fetch-liboqs.sh
cmake -S third_party/liboqs -B third_party/build-host-static -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65" >/dev/null
cmake --build third_party/build-host-static >/dev/null
JH=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(which javac)")")")}
mkdir -p third_party/jni-host
gcc -shared -fPIC -O2 -Ithird_party/build-host-static/include -I"$JH/include" -I"$JH/include/linux" \
  native/nocoqs/oqs_jni.c third_party/build-host-static/lib/liboqs.a -o third_party/jni-host/libnocoqs.so
ls -la third_party/jni-host/libnocoqs.so
