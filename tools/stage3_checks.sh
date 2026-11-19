#!/usr/bin/env bash
# Stage 3 (server + superadmin) and the phone-loss / malware / impersonation block.
# Rule: any finding -> fix -> run EVERYTHING again from the top.
set -u
cd "$(dirname "$0")/.."
fail=0; n=0
ok()  { n=$((n+1)); echo "  PASS  [$n] $1"; }
bad() { n=$((n+1)); echo "  FAIL  [$n] $1"; fail=1; }
run() { # run <label> <command...>
  local label=$1; shift
  if "$@" >/tmp/s3_step.log 2>&1; then ok "$label"; else bad "$label"; tail -15 /tmp/s3_step.log; fi
}
SERVER_PY="server/.venv/bin/python"
export ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}

echo "== server and superadmin"
run "admin log with own signatures, key change with proof of possession, no remote token route (server tests)" bash -c "cd server && ../$SERVER_PY -m pytest -q tests/test_stage3.py tests/test_server.py tests/test_stage2.py"
run "server runs as unprivileged user; DB is ciphertext and the key is not next to it; token is console-only; lost admin needs physical reset" bash -c "cd server && ../$SERVER_PY -m pytest -q tests/test_stage3_process.py"
run "no IP, keys, tokens or content in the real server's output" bash -c "cd server && ../$SERVER_PY -m pytest -q tests/test_real_process.py"

echo "== firewall and system rules"
run "firewall behaviour: in/out default-drop, only the Tor process may go out, loopback works, no port exceptions" bash tools/firewall_test.sh
run "firewall rules parse (nft -c)" nft -c -f server/deploy/firewall.nft
cat > /tmp/ss_good <<'T'
tcp LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*
tcp LISTEN 0 128 [::1]:9050 [::]:*
T
cat > /tmp/ss_bad <<'T'
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
T
printf 'tor\npython\n' > /tmp/ps_good; printf 'tor\nsshd\n' > /tmp/ps_bad; printf 'tor\ntailscaled\n' > /tmp/ps_ts
audit_ok=1
NOC_AUDIT_SS=/tmp/ss_good NOC_AUDIT_PS=/tmp/ps_good bash server/deploy/audit.sh >/dev/null || audit_ok=0
NOC_AUDIT_SS=/tmp/ss_bad  NOC_AUDIT_PS=/tmp/ps_good bash server/deploy/audit.sh >/dev/null && audit_ok=0
NOC_AUDIT_SS=/tmp/ss_good NOC_AUDIT_PS=/tmp/ps_bad  bash server/deploy/audit.sh >/dev/null && audit_ok=0
NOC_AUDIT_SS=/tmp/ss_good NOC_AUDIT_PS=/tmp/ps_ts   bash server/deploy/audit.sh >/dev/null && audit_ok=0
[ $audit_ok = 1 ] && ok "audit.sh accepts a clean host and flags: a public listener, sshd, tailscaled" || bad "audit.sh misjudged a sample"
grep -q "socks5h://127.0.0.1:9050" server/deploy/apt-tor.conf && grep -q "^SocksPort 127.0.0.1:9050" server/deploy/torrc.noc && ! grep -qE "^(ListenAddress|ORPort|DirPort)" server/deploy/torrc.noc \
  && ok "updates go through Tor (apt socks5h), Tor SOCKS is loopback-only, no relay ports" || bad "Tor/apt configuration"
run "Tor accepts the onion-service configuration (tor --verify-config)" bash -c "tor --verify-config -f <(sed 's#/var/lib/tor#/tmp/torT/svc#g; s#Log notice file .*#Log notice stdout#' server/deploy/torrc.noc)"
! grep -rqiE "(install|enable|start|--now)[^#]*(openssh|sshd|tailscale|zerotier)|ssh -R|authorized_keys" server/deploy/*.sh server/deploy/*.conf server/deploy/torrc.noc 2>/dev/null && ok "nothing in the deployment files installs or enables SSH, Tailscale or similar" || bad "deployment files install/enable remote access"

echo "== client: phone left open / lost, malware, impersonation"
run "administrator key rotation + signed actions against the real server; impersonation and key-change tests; all client tests" bash -c "cd client-android && gradle --no-daemon -q :core-crypto:test :core-client:test"
M=client-android/app/src/main
chk=1
grep -q "FLAG_SECURE" $M/kotlin/noc/app/MainActivity.kt || chk=0
grep -q 'android:allowBackup="false"' $M/AndroidManifest.xml || chk=0
grep -q "setUserAuthenticationRequired(true)" $M/kotlin/noc/app/security/KeyVault.kt || chk=0
grep -q "Integrity.problem" $M/kotlin/noc/app/MainActivity.kt || chk=0
grep -q "postDelayed(lockRunnable" $M/kotlin/noc/app/MainActivity.kt || chk=0
[ -z "$(grep -rnE 'Log\.|println|printStackTrace|ClipboardManager|setPrimaryClip' client-android/*/src/main)" ] || chk=0
[ $chk = 1 ] && ok "screen capture blocked, no backup, Keystore needs fresh auth, integrity check, auto-lock, no logs/clipboard" || bad "a phone-side safeguard is missing"
for f in docs/security-checks/stage1-client.md; do :; done

echo
echo "$n checks run"
[ $fail = 0 ] && echo "ALL CHECKS PASSED" || echo "FINDINGS: fix and run again from the top"
exit $fail
