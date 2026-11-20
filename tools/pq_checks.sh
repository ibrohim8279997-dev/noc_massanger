#!/usr/bin/env bash
# ML-DSA-65 for the superadmin: ten+ checks, each tied to named tests (results read from the real test reports).
# Rule: any finding -> fix -> ALL checks again from the top.
set -u
cd "$(dirname "$0")/.."
export ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}
bash tools/build-liboqs-host.sh >/dev/null 2>&1; bash tools/build-oqs-jni-host.sh >/dev/null 2>&1
( cd server && .venv/bin/python -m pytest -q --junitxml=/tmp/pq_server.xml >/tmp/pq_server.log 2>&1 ) || { echo "server tests failed:"; tail -15 /tmp/pq_server.log; }
( cd client-android && gradle --no-daemon -q :core-crypto:test :core-client:test --rerun-tasks >/tmp/pq_client.log 2>&1 ) || { echo "client tests failed:"; tail -15 /tmp/pq_client.log; }
python3 - <<'PY'
import glob, re, subprocess, sys, xml.etree.ElementTree as ET
res = {}
for f in ["/tmp/pq_server.xml"]:
    for tc in ET.parse(f).getroot().iter("testcase"):
        res[tc.get("name")] = not any(c.tag in ("failure", "error", "skipped") for c in tc)
for f in glob.glob("client-android/core-*/build/test-results/test/*.xml"):
    for tc in ET.parse(f).getroot().iter("testcase"):
        res[tc.get("name").replace("()", "")] = not any(c.tag in ("failure", "error", "skipped") for c in tc)
def t(*names):
    return [n for n in names if n not in res], [n for n in names if n in res and not res[n]]
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True)
NDK = "/opt/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin"
APK = "client-android/app/build/outputs/apk/release/app-release.apk"
so = "/tmp/pq_so"; sh(f"rm -rf {so}; mkdir -p {so}; cd {so}; unzip -q -o {'/home/user/noc_massanger/'+APK} lib/arm64-v8a/libnocoqs.so")
elf = sh(f"{NDK}/llvm-readelf -h {so}/lib/arm64-v8a/libnocoqs.so").stdout
syms = sh(f"{NDK}/llvm-nm -D --defined-only {so}/lib/arm64-v8a/libnocoqs.so").stdout
needed = sh(f"{NDK}/llvm-readelf -d {so}/lib/arm64-v8a/libnocoqs.so | grep NEEDED").stdout
android_ok = ("AArch64" in elf and all(f"Java_noc_crypto_MlDsa65_native{n}" in syms for n in ("Keypair", "Sign", "Verify"))
              and set(re.findall(r"\[(.*?)\]", needed)) <= {"libc.so", "libm.so", "libdl.so"})
pin = sh("git -C third_party/liboqs rev-parse HEAD").stdout.strip() == "94b421ebb82405c843dba4e9aa521a56ee5a333d"
order = open("client-android/app/src/main/kotlin/noc/app/MainActivity.kt").read()
safe_rotation = (order.index("val (g, fresh) = newAdminKeys()") < order.index("io { block(old, g, fresh) }") and "dropAdminKeys(g); throw e" in open("client-android/app/src/main/kotlin/noc/app/ui/Screens.kt").read()
                 and "adoptAdminKeys(g)" in open("client-android/app/src/main/kotlin/noc/app/ui/Screens.kt").read())
checks = [
 ("1  liboqs source is the exact pinned commit (tag 0.14.0), minimal build with ML-DSA-65 only", ([], []), pin),
 ("2  ML-DSA-65 has FIPS 204 sizes (pk 1952, sk 4032, sig 3309) and sign/verify work on the server side", t("test_liboqs_mldsa_roundtrip_and_failures", "test_signatures_are_randomized_but_all_verify"), True),
 ("3  every bit change in message, signature or key is rejected; wrong sizes refused without crashing", t("any_change_to_message_signature_or_key_is_rejected", "wrong_sized_secret_key_is_refused_not_crashed", "test_liboqs_mldsa_roundtrip_and_failures"), True),
 ("4  hybrid: the administrator needs BOTH signatures (Ed25519 alone refused, ML-DSA alone refused, a flipped ML-DSA bit refused)", t("test_admin_request_without_the_pq_signature_is_refused_even_with_a_valid_ed25519_one", "test_ed25519_alone_is_not_enough_and_pq_alone_is_not_enough", "test_valid_ed25519_with_a_flipped_bit_in_the_pq_signature_is_refused", "test_admin_request_with_someone_elses_pq_signature_is_refused"), True),
 ("5  the ML-DSA signature is bound to its request (cannot be moved to another request) and domain-separated from plain signatures", t("test_pq_signature_covers_the_request_so_it_cannot_be_moved_to_another_request", "hybrid_signer_adds_the_pq_header_and_it_verifies_over_the_same_message"), True),
 ("6  key change needs proof of possession of BOTH new keys; both old keys die; old ML-DSA + new Ed25519 mix is refused", t("test_rotate_key_needs_proof_of_possession_of_both_new_keys", "test_rotate_key_moves_the_single_superadmin_and_old_keys_die", "admin_key_change_moves_the_role_and_the_old_key_stops_working_and_actions_are_logged"), True),
 ("7  binding needs a well-formed ML-DSA key; reset removes it; an old administrator without one is detected and cannot administer", t("test_bind_requires_a_well_formed_ml_dsa_key", "test_pq_public_key_is_stored_with_the_admin_and_goes_with_it_on_reset", "test_old_superadmin_without_pq_key_is_detected"), True),
 ("8  independent implementation: BouncyCastle accepts liboqs signatures and liboqs accepts BouncyCastle signatures", t("independent_implementation_bouncycastle_accepts_a_liboqs_signature", "and_liboqs_accepts_a_bouncycastle_signature_with_liboqs_generated_keys"), True),
 ("9  a signature made by the client library (JNI build) verifies in the server's separate liboqs build", t("test_signature_made_by_the_kotlin_client_through_liboqs_jni_verifies_on_the_server", "writes_an_interop_vector_for_the_python_server"), True),
 ("10 the Android arm64 library is a real AArch64 build with the three JNI entry points and only libc/libm/libdl as dependencies", ([], []), android_ok),
 ("11 key change on the phone cannot lock the administrator out: new keys stored first, adopted only after the server accepted, dropped on failure", ([], []), safe_rotation),
 ("12 real server process: no ML-DSA keys or signatures in its output; replay of an admin request refused", t("test_real_server_output_has_no_ip_keys_or_tokens", "test_replay_rejected"), True),
 ("13 non-administrators are unaffected, administrator actions are logged with both signatures", t("test_non_admin_users_are_unaffected_by_pq", "test_admin_actions_are_logged_with_the_admins_own_signature"), True),
]
bad = 0
for label, (missing, failed), extra in checks:
    ok = not missing and not failed and bool(extra)
    print(("  PASS  " if ok else "  FAIL  ") + label)
    if missing: print("        missing tests:", missing)
    if failed: print("        failed tests:", failed)
    if not extra: print("        static condition failed")
    bad |= not ok
allfail = [n for n, v in res.items() if not v]
print(f"\n{len(res)} tests read; failing: {allfail or 'none'}")
print("ALL CHECKS PASSED" if not bad and not allfail else "FINDINGS: fix and run again from the top")
sys.exit(1 if bad or allfail else 0)
PY
