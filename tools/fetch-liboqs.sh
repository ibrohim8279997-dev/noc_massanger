#!/usr/bin/env bash
# Downloads liboqs at an exact, pinned commit (a moved tag or a tampered mirror is refused).
set -e
cd "$(dirname "$0")/.."
TAG=0.14.0
PIN=94b421ebb82405c843dba4e9aa521a56ee5a333d
if [ ! -d third_party/liboqs/.git ]; then
  git clone --quiet --depth 1 --branch "$TAG" https://github.com/open-quantum-safe/liboqs third_party/liboqs
fi
HEAD=$(git -C third_party/liboqs rev-parse HEAD)
[ "$HEAD" = "$PIN" ] || { echo "liboqs commit mismatch: $HEAD (expected $PIN). Delete third_party/liboqs and check the source."; exit 1; }
echo "liboqs $TAG at $PIN"
