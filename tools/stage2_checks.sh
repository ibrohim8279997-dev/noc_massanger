#!/usr/bin/env bash
# Stage 2 security checks that can run without a phone. Rule: any finding -> fix -> run ALL checks again from the top.
set -u
cd "$(dirname "$0")/.."
fail=0
ok()  { echo "  PASS  $1"; }
bad() { echo "  FAIL  $1"; fail=1; }

echo "[1] no network access outside the Tor-aware transport"
n=$(grep -rnE "HttpURLConnection|openConnection|java\.net\.Socket\(|DatagramSocket|InetAddress\.get|WebView|Cronet|DownloadManager" client-android/*/src/main | wc -l)
[ "$n" = 0 ] && ok "no raw sockets/URL connections in app or libraries" || bad "raw network API found ($n)"
c=$(grep -rn "OkHttpClient.Builder" client-android/*/src/main | wc -l)
[ "$c" = 1 ] && ok "exactly one OkHttp construction site (Transport.base)" || bad "OkHttp built in $c places"
grep -q "http: OkHttpClient)" client-android/core-client/src/main/kotlin/noc/client/ServerApi.kt && ok "ServerApi has no default transport" || bad "ServerApi has a default transport"

echo "[2-3] DNS, fail-closed, onion guard (fake SOCKS proxy)"
echo "[4-6,7',8'] sizes, constant rate, jitter, rotation (cover/e2e tests)"
( cd client-android && ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk} gradle --no-daemon -q :core-crypto:test :core-client:test >/tmp/s2_client.log 2>&1 ) && ok "core-crypto + core-client tests" || { bad "client tests"; tail -20 /tmp/s2_client.log; }
t=$(grep -ho 'tests="[0-9]*"' client-android/core-client/build/test-results/test/*.xml client-android/core-crypto/build/test-results/test/*.xml | tr -dc '0-9\n' | paste -sd+ | bc)
echo "        ($t client-side tests ran)"

echo "[4,5,8',9] server: fixed slots, rate limits, deletion, no secrets in the real process output"
( cd server && . .venv/bin/activate && python -m pytest -q >/tmp/s2_server.log 2>&1 ) && ok "server tests ($(grep -o '[0-9]* passed' /tmp/s2_server.log))" || { bad "server tests"; tail -20 /tmp/s2_server.log; }

echo "[9] no logging calls in client code that could carry keys, addresses or text"
l=$(grep -rnE "Log\.|println|printStackTrace|Timber" client-android/*/src/main | wc -l)
[ "$l" = 0 ] && ok "no log calls" || bad "log calls found ($l)"

echo "[10] firewall: stage 3 (needs the server phone) - not run here"
[ $fail = 0 ] && echo "ALL CHECKS PASSED" || echo "FINDINGS: fix and run again from the top"
exit $fail
