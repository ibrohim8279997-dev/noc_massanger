package noc.client

import noc.client.CoverChannel.Companion.D_HAS_PACKET
import noc.client.CoverChannel.Companion.D_REJECTED
import noc.client.CoverChannel.Companion.ENVELOPE
import noc.client.CoverChannel.Companion.F_ACK
import noc.client.CoverChannel.Companion.F_UPLOAD
import noc.client.CoverChannel.Companion.SLOT_DOWN
import noc.client.CoverChannel.Companion.SLOT_UP
import java.security.SecureRandom
import kotlin.test.*

private class FakeServer : Exchanger {
    val slots = ArrayList<ByteArray>()
    var reply: (ByteArray) -> ByteArray = { empty() }
    var fail = false
    fun empty(flags: Int = 0, pid: ByteArray = ByteArray(16), data: ByteArray = ByteArray(ENVELOPE)) = byteArrayOf(flags.toByte()) + pid + data
    override fun exchange(slot: ByteArray): ByteArray { if (fail) error("network down"); slots.add(slot); return reply(slot) }
}

class CoverTest {
    private val box = ByteArray(16) { 1 } to ByteArray(32) { 2 }
    private fun chan(s: FakeServer, mode: () -> CoverMode = { CoverMode.NORMAL }, clock: () -> Long = { 0L }, onPacket: (ByteArray) -> Unit = {}) =
        CoverChannel(s, { listOf(box) }, mode, onPacket, clock = clock, activePeriodMs = 2000, idlePeriodMs = 30_000, activeWindowMs = 180_000)

    @Test fun every_slot_has_the_same_size_real_or_dummy() {
        val s = FakeServer(); val c = chan(s)
        c.exchangeOnce()                                           // pure dummy
        c.enqueue(ByteArray(16) { 9 }, ByteArray(ENVELOPE) { 5 }); c.exchangeOnce()   // real upload
        c.exchangeOnce()
        assertEquals(setOf(SLOT_UP), s.slots.map { it.size }.toSet())
        assertEquals(F_UPLOAD, s.slots[1][0].toInt() and F_UPLOAD)
        assertEquals(0, s.slots[0][0].toInt() and F_UPLOAD)
    }

    @Test fun real_message_replaces_the_dummy_and_dummies_are_random() {
        val s = FakeServer(); val c = chan(s)
        val env = ByteArray(ENVELOPE) { 7 }
        c.enqueue(ByteArray(16) { 3 }, env); c.exchangeOnce(); c.exchangeOnce(); c.exchangeOnce()
        assertContentEquals(env, s.slots[0].copyOfRange(81, SLOT_UP))               // real one went into the first slot
        assertNotEquals(s.slots[1].copyOfRange(81, SLOT_UP).toList(), s.slots[2].copyOfRange(81, SLOT_UP).toList())   // dummies differ
        assertTrue(s.slots[1].copyOfRange(81, SLOT_UP).toSet().size > 200)         // and look like noise
    }

    @Test fun rate_is_constant_in_silence_and_during_conversation() {
        // simulated clock: run() sleeps exactly the remainder of the period
        var now = 0L; val s = FakeServer(); val times = ArrayList<Long>()
        val ex = object : Exchanger { override fun exchange(slot: ByteArray): ByteArray { times.add(now); now += 300; return s.empty() } }   // each exchange "takes" 300 ms
        val c = CoverChannel(ex, { listOf(box) }, { CoverMode.PARANOID }, {}, clock = { now }, paranoidPeriodMs = 2000)
        var n = 0
        c.run({ n++ >= 400 }, sleep = { now += it })
        val gaps = times.zipWithNext { a, b -> b - a }.toSet()
        assertEquals(setOf(2000L), gaps)                                           // exactly one slot per period
        // now with real traffic mixed in: the rhythm must not change
        times.clear(); n = 0
        val c2 = CoverChannel(ex, { listOf(box) }, { CoverMode.PARANOID }, {}, clock = { now }, paranoidPeriodMs = 2000)
        repeat(5) { c2.enqueue(ByteArray(16), ByteArray(ENVELOPE)) }
        c2.run({ n++ >= 400 }, sleep = { now += it })
        assertEquals(setOf(2000L), times.zipWithNext { a, b -> b - a }.toSet())
    }

    @Test fun normal_mode_is_active_after_use_then_idles_paranoid_never_does() {
        var now = 0L; val s = FakeServer()
        val normal = chan(s, { CoverMode.NORMAL }, { now })
        assertEquals(30_000, normal.periodMs())                                   // idle: slow heartbeat
        normal.enqueue(ByteArray(16), ByteArray(ENVELOPE)); assertEquals(2000, normal.periodMs())   // user sent something
        now = 179_000; assertEquals(2000, normal.periodMs())                       // still within the window
        now = 181_000; assertEquals(30_000, normal.periodMs())                     // quiet again
        val par = chan(s, { CoverMode.PARANOID }, { now }); assertEquals(5000, par.periodMs())
        now = 10_000_000; assertEquals(5000, par.periodMs())
    }

    @Test fun incoming_packet_is_delivered_once_acked_and_next_slot_carries_the_ack() {
        val s = FakeServer(); val got = ArrayList<ByteArray>()
        val pid = ByteArray(16) { 4 }; val data = ByteArray(ENVELOPE) { 6 }
        var served = false
        s.reply = { slot -> if (!served || slot[0].toInt() and F_ACK == 0) { served = true; s.empty(D_HAS_PACKET, pid, data) } else s.empty() }
        val c = chan(s, onPacket = { got.add(it) })
        c.exchangeOnce(); c.exchangeOnce(); c.exchangeOnce()
        assertEquals(1, got.size); assertContentEquals(data, got[0])              // a repeated packet is not delivered twice
        assertEquals(0, s.slots[0][0].toInt() and F_ACK)
        assertEquals(F_ACK, s.slots[1][0].toInt() and F_ACK)                       // acknowledgement rides in the next slot
        assertContentEquals(pid, s.slots[1].copyOfRange(49, 65))
    }

    @Test fun failed_exchange_keeps_the_message_for_the_next_slot() {
        val s = FakeServer(); val c = chan(s)
        c.enqueue(ByteArray(16), ByteArray(ENVELOPE) { 8 })
        s.fail = true; assertFalse(c.exchangeOnce()); assertEquals(1, c.queued())
        s.fail = false; assertTrue(c.exchangeOnce()); assertEquals(0, c.queued())
    }

    @Test fun rejected_upload_is_retried_then_reported() {
        val s = FakeServer(); val failed = ArrayList<ByteArray>()
        s.reply = { s.empty(D_REJECTED) }
        val c = CoverChannel(s, { listOf(box) }, { CoverMode.NORMAL }, {}, onUploadFailed = { failed.add(it) }, maxTries = 3)
        c.enqueue(ByteArray(16) { 1 }, ByteArray(ENVELOPE)); repeat(5) { c.exchangeOnce() }
        assertEquals(1, failed.size); assertEquals(0, c.queued())
        assertEquals(3, s.slots.count { it[0].toInt() and F_UPLOAD != 0 })
    }

    @Test fun two_mailboxes_are_polled_round_robin() {
        val s = FakeServer(); val b2 = ByteArray(16) { 9 } to ByteArray(32) { 8 }
        val c = CoverChannel(s, { listOf(box, b2) }, { CoverMode.NORMAL }, {})
        repeat(4) { c.exchangeOnce() }
        assertEquals(listOf(box.first.toList(), b2.first.toList(), box.first.toList(), b2.first.toList()), s.slots.map { it.copyOfRange(1, 17).toList() })
    }

    @Test fun wrong_response_size_is_not_trusted() {
        val s = FakeServer(); s.reply = { ByteArray(10) }
        assertFalse(chan(s).exchangeOnce())
    }
}
