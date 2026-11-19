package noc.mesh

import java.io.File
import java.security.SecureRandom
import kotlin.test.*

private val rnd = SecureRandom()
private fun rb(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

class EnvelopeTest {
    private val circle = MeshCircle(rb(32))
    private fun env(body: ByteArray = rb(300), exp: Long = 99_999) = MeshEnvelope.build(circle, body, exp)

    @Test fun every_envelope_is_exactly_4096_bytes_whatever_the_message() {
        assertEquals(setOf(MESH_ENVELOPE), listOf(1, 50, 600, 2000, MeshEnvelope.MAX_BODY).map { env(rb(it)).size }.toSet())
    }

    @Test fun header_fields_are_fresh_per_message_so_nothing_identifies_a_sender() {
        val body = rb(300); val es = (1..30).map { MeshEnvelope.parse(env(body))!! }
        assertEquals(30, es.map { hex(it.id) }.toSet().size); assertEquals(30, es.map { hex(it.eph) }.toSet().size)
        assertEquals(30, es.map { hex(it.sig) }.toSet().size); assertEquals(30, es.map { hex(it.tag) }.toSet().size)
        assertEquals(30, (1..30).map { hex(env(body).copyOfRange(MeshEnvelope.HEADER + 300, MESH_ENVELOPE)) }.toSet().size)   // padding is random too
    }

    @Test fun valid_envelope_verifies_and_hop_changes_do_not_break_it() {
        val raw = env(); val e = MeshEnvelope.parse(raw)!!
        assertTrue(MeshEnvelope.verify(e, circle))
        assertTrue(MeshEnvelope.verify(MeshEnvelope.parse(MeshEnvelope.withHops(raw, 5))!!, circle))
        assertEquals(5, MeshEnvelope.parse(MeshEnvelope.withHops(raw, 5))!!.hops)
    }

    @Test fun tampering_with_any_signed_part_is_detected() {
        val raw = env()
        for (pos in listOf(1, 17, 20, MeshEnvelope.HEADER + 5)) {                          // id, expiry, body
            val bad = raw.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }
            val e = MeshEnvelope.parse(bad); assertTrue(e == null || !MeshEnvelope.verify(e, circle), "pos $pos")
        }
        for (pos in listOf(22, 54, 118)) {                                                  // eph key, signature, tag
            val bad = raw.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }
            assertFalse(MeshEnvelope.verify(MeshEnvelope.parse(bad)!!, circle), "pos $pos")
        }
    }

    @Test fun outsiders_without_the_circle_key_are_rejected_even_with_a_valid_signature() {
        val foreign = MeshEnvelope.build(MeshCircle(rb(32)), rb(100), 99_999)
        assertFalse(MeshEnvelope.verify(MeshEnvelope.parse(foreign)!!, circle))
    }

    @Test fun malformed_input_is_refused() {
        assertNull(MeshEnvelope.parse(ByteArray(100))); assertNull(MeshEnvelope.parse(ByteArray(MESH_ENVELOPE)))
        assertFailsWith<IllegalArgumentException> { MeshEnvelope.build(circle, rb(MeshEnvelope.MAX_BODY + 1), 1) }
        assertFailsWith<IllegalArgumentException> { MeshEnvelope.build(circle, ByteArray(0), 1) }
        val bad = env().also { it[134] = 0xff.toByte(); it[135] = 0xff.toByte() }; assertNull(MeshEnvelope.parse(bad))        // impossible length
    }
}

class FragmentTest {
    private val envelope = rb(MESH_ENVELOPE)

    @Test fun roundtrip_in_any_order_with_duplicates() {
        val frags = Fragments.split(envelope).shuffled() + Fragments.split(envelope).take(0)
        val r = Fragments.Reassembler(); (frags + frags.take(5)).forEach { assertTrue(r.add(it)) }
        assertContentEquals(envelope, r.result())
    }

    @Test fun every_fragment_fits_a_small_radio_packet() {
        assertTrue(Fragments.split(envelope).all { it.size <= Fragments.PAYLOAD + 13 })
    }

    @Test fun missing_fragments_are_reported_and_can_be_filled_in_later() {
        val frags = Fragments.split(envelope); val r = Fragments.Reassembler()
        frags.forEachIndexed { i, f -> if (i % 4 != 1) r.add(f) }
        assertEquals(frags.indices.filter { it % 4 == 1 }, r.missing()); assertNull(r.result())
        frags.forEachIndexed { i, f -> if (i % 4 == 1) r.add(f) }
        assertContentEquals(envelope, r.result())
    }

    @Test fun corrupted_foreign_and_nonsense_fragments_are_refused() {
        val frags = Fragments.split(envelope); val r = Fragments.Reassembler()
        assertTrue(r.add(frags[0]))
        assertFalse(r.add(frags[1].copyOf().also { it[12] = (it[12].toInt() xor 1).toByte() }))     // bad crc
        assertFalse(r.add(Fragments.split(envelope, session = 7)[1]))                                 // other transfer
        assertFalse(r.add(ByteArray(5))); assertFalse(r.add(ByteArray(40)))
        assertFalse(r.complete())
    }

    @Test fun whole_envelope_checksum_catches_what_per_fragment_crc_cannot() {
        // an attacker who fixes the crc of each fragment but changes the data still fails the SHA-256 of the envelope
        val frags = Fragments.split(envelope)
        val r = Fragments.Reassembler()
        frags.forEachIndexed { i, f ->
            val b = f.copyOf()
            if (i == 3) { b[10] = (b[10].toInt() xor 1).toByte(); val crc = java.util.zip.CRC32().apply { update(b, 0, b.size - 4) }.value.toInt(); java.nio.ByteBuffer.wrap(b, b.size - 4, 4).putInt(crc) }
            assertTrue(r.add(b))
        }
        assertTrue(r.complete()); assertNull(r.result())
    }
}

class StoreTest {
    private val key = rb(32)
    private val secret = "TOP-SECRET-PLAINTEXT-MARKER-".toByteArray()

    @Test fun memory_store_returns_data_only_with_the_right_key() {
        val s = EncryptedMemoryStore(key); val id = rb(16); s.put(id, secret + rb(50))
        assertContentEquals(secret, s.get(id)!!.copyOf(secret.size))
        assertNull(s.get(rb(16)))                                                                        // unknown id: nothing
        assertFalse(deepContains(s, secret))                                                             // nothing readable is held in the object
    }

    @Test fun file_store_writes_only_ciphertext_with_random_names_and_no_key() {
        val dir = createTempDir("mesh"); val s = EncryptedFileStore(dir, key); val id = rb(16)
        s.put(id, secret + rb(100))
        val f = dir.listFiles()!!.single(); val bytes = f.readBytes()
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains(String(secret)))                          // no plaintext on disk
        assertFalse(String(bytes, Charsets.ISO_8859_1).contains(String(key, Charsets.ISO_8859_1)))        // key never written
        assertFalse(f.name.contains(hex(id)))                                                             // the file name does not leak the message id
        assertContentEquals(secret, s.get(id)!!.copyOf(secret.size))
    }

    @Test fun deleting_overwrites_the_data_before_removing_the_file() {
        val dir = createTempDir("mesh"); val s = EncryptedFileStore(dir, key); val id = rb(16)
        s.put(id, secret + rb(100))
        val f = dir.listFiles()!!.single(); val link = File(dir.parentFile, "link-" + f.name)
        java.nio.file.Files.createLink(link.toPath(), f.toPath())                                         // keeps the same disk blocks reachable after delete
        val before = link.readBytes(); assertTrue(before.any { it != 0.toByte() })
        s.delete(id)
        assertTrue(dir.listFiles()!!.isEmpty()); assertEquals(0, s.count())
        assertTrue(link.readBytes().all { it == 0.toByte() }, "the old blocks were zeroed")
        link.delete()
    }

    @Test fun leftovers_from_a_previous_run_are_destroyed_at_start() {
        val dir = createTempDir("mesh"); File(dir, "old.bin").writeBytes(rb(500))
        EncryptedFileStore(dir, key); assertTrue(dir.listFiles()!!.isEmpty())
    }

    @Test fun wipe_clears_everything_and_a_garbled_file_reads_as_nothing() {
        val dir = createTempDir("mesh"); val s = EncryptedFileStore(dir, key); val id = rb(16)
        s.put(id, secret); dir.listFiles()!!.single().also { it.writeBytes(it.readBytes().also { b -> b[20] = (b[20].toInt() xor 1).toByte() }) }
        assertNull(s.get(id))                                                                              // tampering with the file is detected (GCM)
        s.put(rb(16), secret); s.wipe(); assertEquals(0, s.count()); assertTrue(dir.listFiles()!!.isEmpty())
    }
}

class AdvertTest {
    private val circle = MeshCircle(rb(32)); private val planner = AdvertPlanner(circle, slotMs = 300_000)

    @Test fun nothing_persistent_or_identifying_is_advertised() {
        val a = planner.advertise(1_000_000)
        assertFalse(a.includeName); assertFalse(a.includeTxPower); assertNull(a.manufacturerData); assertEquals(16, a.serviceUuid.size)
    }

    @Test fun the_identifier_changes_every_few_minutes_and_never_repeats() {
        val seen = (0 until 500).map { hex(planner.advertise(it * 300_000L).serviceUuid) }
        assertEquals(500, seen.toSet().size)                                                                // 500 slots (~35 hours): all different
        assertEquals(hex(planner.advertise(300_000).serviceUuid), hex(planner.advertise(599_999).serviceUuid))   // stable inside a slot
        assertNotEquals(hex(planner.advertise(599_999).serviceUuid), hex(planner.advertise(600_000).serviceUuid))
    }

    @Test fun no_byte_position_is_constant_across_slots() {
        val all = (0 until 400).map { planner.advertise(it * 300_000L).serviceUuid }
        for (pos in 0 until 16) assertTrue(all.map { it[pos] }.toSet().size > 100, "byte $pos looks constant")
    }

    @Test fun members_find_each_other_across_small_clock_differences_outsiders_do_not() {
        val now = 10 * 300_000L + 299_000        // end of a slot: a neighbour whose clock runs fast is already in the next one
        val member = AdvertPlanner(circle, 300_000); val outsider = AdvertPlanner(MeshCircle(rb(32)), 300_000)
        assertTrue(member.scanFor(now).any { it.contentEquals(planner.advertise(now + 5_000).serviceUuid) })
        assertTrue(member.scanFor(now).none { it.contentEquals(outsider.advertise(now).serviceUuid) })
    }

    @Test fun the_characteristic_rotates_too_and_differs_from_the_service_id() {
        assertNotEquals(hex(planner.advertise(1_000_000).serviceUuid), hex(planner.characteristicUuid(1_000_000)))
        assertEquals(300, (0 until 300).map { hex(planner.characteristicUuid(it * 300_000L)) }.toSet().size)
    }

    @Test fun the_identifier_does_not_depend_on_the_device() {
        // two different phones of the same circle advertise the same value: it cannot single one phone out
        assertContentEquals(AdvertPlanner(MeshCircle(circle.key.copyOf())).advertise(5_000_000).serviceUuid, planner.advertise(5_000_000).serviceUuid)
    }
}

class CodecTest {
    @Test fun messages_roundtrip_and_garbage_is_refused() {
        val h = MeshMsg.Hello(listOf(1L, -5L, Long.MAX_VALUE))
        assertEquals(listOf(1L, -5L, Long.MAX_VALUE), (MeshMsg.decode(h.encode()) as MeshMsg.Hello).hashes)
        assertEquals(7L, (MeshMsg.decode(MeshMsg.Ack(7).encode()) as MeshMsg.Ack).hash)
        val env = rb(MESH_ENVELOPE); assertContentEquals(env, (MeshMsg.decode(MeshMsg.Env(env).encode()) as MeshMsg.Env).envelope)
        assertNull(MeshMsg.decode(ByteArray(0))); assertNull(MeshMsg.decode(byteArrayOf(9, 1, 2))); assertNull(MeshMsg.decode(byteArrayOf(1, 0, 5)))
        assertNull(MeshMsg.decode(MeshMsg.Ack(1).encode() + byteArrayOf(0)))                                          // trailing bytes
    }
}
