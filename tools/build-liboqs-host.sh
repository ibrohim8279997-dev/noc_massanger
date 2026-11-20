#!/usr/bin/env bash
# Builds liboqs for THIS machine (server phone or build host) with ML-DSA-65 only. Output: third_party/build-host/lib/liboqs.so
set -e
cd "$(dirname "$0")/.."
bash tools/fetch-liboqs.sh
cmake -S third_party/liboqs -B third_party/build-host -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65" -DCMAKE_INSTALL_PREFIX=third_party/build-host/install >/dev/null
cmake --build third_party/build-host >/dev/null
ls -la third_party/build-host/lib/liboqs.so*
