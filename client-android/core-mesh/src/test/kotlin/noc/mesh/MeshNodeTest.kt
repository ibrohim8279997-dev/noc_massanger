package noc.mesh

import java.security.SecureRandom
import kotlin.test.*

private val rnd = SecureRandom()
private fun rb(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

class NodeTest {
    private val circle = MeshCircle(rb(32))
    private var now = 1_000_000_000L
    private fun relay(limits: Limits = Limits(), store: EnvelopeStore = EncryptedMemoryStore(rb(32)), deliver: (ByteArray) -> Boolean = { false }) =
        MeshNode(circle, store, { now }, deliver, limits)

    @Test fun envelope_is_kept_until_enough_neighbours_acknowledged_then_deleted() {
        val a = relay(Limits(fanout = 3)); a.inject(rb(300))
        val others = List(3) { relay() }
        encounter(a, others[0]); assertEquals(1, a.held()); assertEquals(1, others[0].held())          // one hand-off: still kept
        encounter(a, others[1]); assertEquals(1, a.held())                                              // two: still kept
        encounter(a, others[2]); assertEquals(0, a.held()); assertEquals(0, a.stored())                  // three acknowledged: gone
    }

    @Test fun without_an_acknowledgement_nothing_is_deleted() {
        val a = relay(Limits(fanout = 1)); a.inject(rb(300)); val b = relay()
        encounter(a, b, lose = { it is MeshMsg.Ack })                                                   // the ack never arrives
        assertEquals(1, a.held()); assertEquals(1, a.stored())                                          // so a keeps its copy
        encounter(a, b)                                                                                 // later: b already has it and acks again
        assertEquals(0, a.held())
    }

    @Test fun envelopes_expire_exactly_at_their_ttl_and_not_before() {
        val a = relay(Limits(ttlMinutes = 60)); a.inject(rb(300))
        now += 59 * 60_000L; a.purge(); assertEquals(1, a.held())
        now += 2 * 60_000L; a.purge(); assertEquals(0, a.held()); assertEquals(0, a.stored())
    }

    @Test fun expired_envelopes_are_not_offered_or_accepted() {
        val a = relay(Limits(ttlMinutes = 10)); a.inject(rb(300)); val b = relay(Limits(ttlMinutes = 10))
        now += 11 * 60_000L
        assertEquals(0, encounter(a, b).let { b.held() })
    }

    @Test fun the_buffer_is_bounded_in_count_and_bytes_and_drops_what_would_expire_first() {
        val a = relay(Limits(maxEntries = 5, maxBytes = 5L * MESH_ENVELOPE))
        repeat(20) { a.inject(rb(200)); now += 60_000 }
        assertEquals(5, a.held()); assertEquals(5, a.stored())
        val tiny = relay(Limits(maxEntries = 100, maxBytes = 3L * MESH_ENVELOPE)); repeat(10) { tiny.inject(rb(100)) }
        assertTrue(tiny.stored() <= 3)                                                                   // the byte limit alone also holds
    }

    @Test fun forged_expired_and_over_travelled_envelopes_are_rejected_without_acknowledgement() {
        val b = relay(); val lb = "x"; b.begin(lb)
        fun feed(raw: ByteArray) = b.handle(lb, MeshMsg.Env(raw))
        val good = MeshEnvelope.build(circle, rb(100), now / 60_000 + 100)
        assertEquals(1, feed(good).size); assertEquals(1, b.held())
        assertTrue(feed(MeshEnvelope.build(MeshCircle(rb(32)), rb(100), now / 60_000 + 100)).isEmpty())             // outsider
        assertTrue(feed(MeshEnvelope.build(circle, rb(100), now / 60_000 - 1)).isEmpty())                            // already expired
        assertTrue(feed(MeshEnvelope.build(circle, rb(100), now / 60_000 + 100_000)).isEmpty())                      // ttl longer than allowed
        assertTrue(feed(MeshEnvelope.withHops(MeshEnvelope.build(circle, rb(100), now / 60_000 + 100), 50)).isEmpty())   // too many hops
        assertTrue(feed(ByteArray(MESH_ENVELOPE)).isEmpty()); assertEquals(1, b.held())
    }

    @Test fun a_neighbour_that_keeps_sending_junk_is_cut_off_for_the_rest_of_the_encounter() {
        val b = relay(Limits(strikesToDrop = 3)); b.begin("p")
        repeat(3) { b.handle("p", MeshMsg.Env(rb(MESH_ENVELOPE))) }
        val good = MeshEnvelope.build(circle, rb(100), now / 60_000 + 100)
        assertTrue(b.handle("p", MeshMsg.Env(good)).isEmpty()); assertEquals(0, b.held())                           // even a good one is ignored now
        b.begin("q"); assertEquals(1, b.handle("q", MeshMsg.Env(good)).size)                                         // a different neighbour is fine
    }

    @Test fun spam_volume_per_encounter_is_capped() {
        val b = relay(Limits(perEncounterIn = 4, maxEntries = 100, maxBytes = 100L * MESH_ENVELOPE)); b.begin("p")
        val acks = (1..10).sumOf { b.handle("p", MeshMsg.Env(MeshEnvelope.build(circle, rb(100), now / 60_000 + 100))).size }
        assertEquals(4, acks); assertEquals(4, b.held())
    }

    @Test fun a_deleted_envelope_is_not_accepted_again_loop_protection() {
        val a = relay(Limits(fanout = 1)); a.inject(rb(300)); val b = relay(Limits(fanout = 1))
        encounter(a, b); assertEquals(0, a.held())
        encounter(b, a); assertEquals(0, a.held())                                                                  // b offers it back: a recognises it
    }

    @Test fun only_hops_below_the_limit_are_forwarded() {
        val l = Limits(maxHops = 2, fanout = 5); val n = List(5) { relay(l) }
        n[0].inject(rb(100))
        encounter(n[0], n[1]); encounter(n[1], n[2]); encounter(n[2], n[3])
        assertEquals(1, n[2].held()); assertEquals(0, n[3].held())                                                   // reached hop 2, goes no further
    }

    @Test fun delivery_consumes_the_message_the_destination_keeps_and_forwards_nothing() {
        val got = ArrayList<ByteArray>(); val dest = relay(deliver = { got.add(it); true }); val a = relay(); val body = rb(300)
        a.inject(body); encounter(a, dest)
        assertEquals(1, got.size); assertContentEquals(body, got[0]); assertEquals(0, dest.held()); assertEquals(0, dest.stored())
    }

    @Test fun a_relay_that_forwarded_everything_keeps_no_trace_of_neighbours_recipient_or_content() {
        val marker = "MARKER-" + hex(rb(6)); val body = marker.toByteArray() + rb(200)
        val a = relay(Limits(fanout = 2)); a.inject(body)
        val r = relay(Limits(fanout = 2)); val x = relay(); val y = relay()
        encounter(a, r); encounter(r, x); encounter(r, y)                                    // r received it and handed it on twice
        assertEquals(0, r.held()); assertEquals(0, r.stored())
        val snap = r.snapshot()
        assertFalse(snap.contains("peer-"), "neighbour label in $snap")                       // no neighbour address/handle
        assertTrue(snap.startsWith("entries=[] "), snap)                                      // no envelope index left
        assertFalse(deepContains(r, marker.toByteArray(), marker))                            // the content is nowhere in memory reachable from the node
        assertEquals(1, r.tombstones())                                                       // only a one-way 64-bit hash of a one-time id remains (loop guard, RAM only)
    }

    @Test fun relays_hold_only_ciphertext_in_their_store() {
        val key = rb(32); val store = EncryptedMemoryStore(key); val a = relay(store = store); val marker = "VISIBLE-IF-NOT-ENCRYPTED"
        a.inject(marker.toByteArray() + rb(100))
        assertFalse(deepContains(a, marker.toByteArray(), marker))                            // not even in the node's own memory
    }

    @Test fun tombstones_age_out_in_generations_without_per_item_times() {
        val a = relay(Limits(ttlMinutes = 10, fanout = 1)); val b = relay(Limits(ttlMinutes = 10, fanout = 1))
        a.inject(rb(100)); encounter(a, b); assertEquals(1, a.tombstones())
        now += 11 * 60_000L; a.purge(); assertEquals(1, a.tombstones())                       // moved to the old generation
        now += 11 * 60_000L; a.purge(); assertEquals(0, a.tombstones())                       // and forgotten
    }
}
