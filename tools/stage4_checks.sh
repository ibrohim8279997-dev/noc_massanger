#!/usr/bin/env bash
# Stage 4 (mesh): ten checks. Each one is tied to named tests whose results are read from the JUnit XML,
# so a check can only pass if those exact tests exist and passed. Rule: any finding -> fix -> ALL ten again from the top.
set -u
cd "$(dirname "$0")/.."
export ANDROID_HOME=${ANDROID_HOME:-/opt/android-sdk}
( cd client-android && gradle --no-daemon -q :core-crypto:test :core-client:test :core-mesh:test --rerun-tasks >/tmp/s4_gradle.log 2>&1 ) || { echo "tests did not all pass:"; tail -20 /tmp/s4_gradle.log; }
python3 - <<'PY'
import glob, re, subprocess, sys
res = {}
for f in glob.glob("client-android/*/build/test-results/test/*.xml"):
    s = open(f).read()
    for m in re.finditer(r'<testcase name="([^"]+)" classname="([^"]+)"[^>]*?(/>|>(.*?)</testcase>)', s, re.S):
        name = m.group(1).replace("()", ""); body = m.group(4) or ""
        res[name] = ("<failure" not in body and "<error" not in body and "<skipped" not in body)
def tests(*names):
    missing = [n for n in names if n not in res]; failed = [n for n in names if n in res and not res[n]]
    return missing, failed
def sh(cmd): return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
checks = [
 ("1  all mesh packets have one length; radio fragments are small", tests("every_envelope_is_exactly_4096_bytes_whatever_the_message", "every_fragment_fits_a_small_radio_packet"), None),
 ("2  nothing persistent in the envelope or the advertisement (random id/key/sig/tag/padding per message; rotating UUIDs, no name/power/manufacturer data)", tests("header_fields_are_fresh_per_message_so_nothing_identifies_a_sender", "nothing_persistent_or_identifying_is_advertised", "no_byte_position_is_constant_across_slots", "the_characteristic_rotates_too_and_differs_from_the_service_id"),
    "! grep -n 'setIncludeDeviceName(true)\\|setIncludeTxPowerLevel(true)\\|addManufacturerData\\|setDeviceName\\|\\.name\\b' client-android/app/src/main/kotlin/noc/app/mesh/BleMesh.kt"),
 ("3  relays carry only ciphertext and cannot read it", tests("a_message_crosses_two_relays_arrives_once_and_relays_cannot_read_it", "relays_hold_only_ciphertext_in_their_store"), None),
 ("4  every message is signed and circle-tagged; forged, outsider, expired, over-travelled, tampered envelopes are rejected", tests("tampering_with_any_signed_part_is_detected", "outsiders_without_the_circle_key_are_rejected_even_with_a_valid_signature", "forged_expired_and_over_travelled_envelopes_are_rejected_without_acknowledgement", "valid_envelope_verifies_and_hop_changes_do_not_break_it", "malformed_input_is_refused"), None),
 ("5  relay buffer is bounded; spam from one neighbour is capped and cut off", tests("the_buffer_is_bounded_in_count_and_bytes_and_drops_what_would_expire_first", "spam_volume_per_encounter_is_capped", "a_neighbour_that_keeps_sending_junk_is_cut_off_for_the_rest_of_the_encounter", "one_hundred_messages_over_a_random_mesh_arrive_exactly_once_each_with_bounded_buffers"), None),
 ("6  files travel as chunks, each with a checksum; missing chunks are requested and re-sent; fragments and whole envelopes are checksummed", tests("a_file_crosses_a_lossy_mesh_missing_chunks_are_requested_and_resent", "missing_fragments_are_reported_and_can_be_filled_in_later", "whole_envelope_checksum_catches_what_per_fragment_crc_cannot", "corrupted_foreign_and_nonsense_fragments_are_refused", "roundtrip_in_any_order_with_duplicates", "corrupted_swapped_or_foreign_chunks_rejected", "whole_file_checksum_is_enforced", "only_the_intended_receiver_can_ask_for_chunks"), None),
 ("7  BLE identifiers rotate every few minutes, are identical for all circle members, and members find each other across clock skew while outsiders do not", tests("the_identifier_changes_every_few_minutes_and_never_repeats", "members_find_each_other_across_small_clock_differences_outsiders_do_not", "the_identifier_does_not_depend_on_the_device"),
    "grep -q 'planner.scanFor' client-android/app/src/main/kotlin/noc/app/mesh/BleMesh.kt && grep -q 'main.postDelayed({ rotate() }' client-android/app/src/main/kotlin/noc/app/mesh/BleMesh.kt"),
 ("8  a relay deletes the envelope and every trace after acknowledgement or expiry, not before; no neighbour label, recipient or content remains in memory", tests("envelope_is_kept_until_enough_neighbours_acknowledged_then_deleted", "without_an_acknowledgement_nothing_is_deleted", "envelopes_expire_exactly_at_their_ttl_and_not_before", "a_relay_that_forwarded_everything_keeps_no_trace_of_neighbours_recipient_or_content", "relays_that_forwarded_the_message_have_nothing_left_and_the_content_is_not_in_their_memory", "tombstones_age_out_in_generations_without_per_item_times", "a_deleted_envelope_is_not_accepted_again_loop_protection"), None),
 ("9  buffer is encrypted at rest with a RAM-only key; deletion overwrites; leftovers are destroyed at start", tests("file_store_writes_only_ciphertext_with_random_names_and_no_key", "deleting_overwrites_the_data_before_removing_the_file", "leftovers_from_a_previous_run_are_destroyed_at_start", "wipe_clears_everything_and_a_garbled_file_reads_as_nothing", "memory_store_returns_data_only_with_the_right_key"),
    "grep -q 'never written anywhere' client-android/app/src/main/kotlin/noc/app/mesh/MeshController.kt && ! grep -nE 'SharedPreferences|openFileOutput|putString|setSetting|writeText|writeBytes' client-android/app/src/main/kotlin/noc/app/mesh/*.kt"),
 ("10 end to end: multi-hop delivery with real Signal sessions exactly once; same message over server and mesh is delivered once; works with no server; mesh code opens no network connections and logs nothing", tests("a_message_crosses_two_relays_arrives_once_and_relays_cannot_read_it", "the_same_message_over_server_and_mesh_is_delivered_only_once", "a_long_chain_delivers_within_the_hop_limit_and_stops_beyond_it", "the_circle_key_converges_along_a_chain_of_meetings_and_outsiders_cannot_join", "delivery_consumes_the_message_the_destination_keeps_and_forwards_nothing"),
    "! grep -rnE 'java\\.net|okhttp|HttpURLConnection|Socket\\(' client-android/core-mesh/src/main && ! grep -rnE 'Log\\.|println|printStackTrace' client-android/core-mesh/src/main client-android/app/src/main/kotlin/noc/app/mesh"),
]
bad = 0
for label, (missing, failed), cmd in checks:
    ok = not missing and not failed
    if cmd and subprocess.run(cmd, shell=True, capture_output=True).returncode != 0: ok = False; failed = failed + ["<static check failed>"]
    print(("  PASS  " if ok else "  FAIL  ") + label)
    if missing: print("        missing tests:", missing)
    if failed: print("        failed:", failed)
    bad |= not ok
total = len(res); fails = [n for n, v in res.items() if not v]
print(f"\n{total} tests read from JUnit results; failing: {fails or 'none'}")
print("ALL TEN CHECKS PASSED" if not bad and not fails else "FINDINGS: fix and run again from the top")
sys.exit(1 if bad or fails else 0)
PY
