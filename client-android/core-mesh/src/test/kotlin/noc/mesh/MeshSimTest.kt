package noc.mesh

import noc.client.*
import noc.crypto.Envelope
import java.security.SecureRandom
import kotlin.test.*

/** Many phones with real Signal sessions and no server at all. Time is simulated. */
class MeshSimTest {
    private var now = 2_000_000_000L
    private val rnd = SecureRandom()

    private fun world(vararg names: String): List<Dev> {
        val devs = names.map { Dev(it) }
        // everybody meets in a chain so that all share ONE circle key, as real people would
        for (i in 0 until devs.size - 1) { val a = devs[i]; val b = devs[i + 1]; meetOffline(a, b) }
        devs.forEach { it.joinMesh({ now }) }
        return devs
    }
    private fun texts(d: Dev, from: Dev) = d.storage.messages(d.contactOf(from).id).filter { !it.outgoing }.map { it.text }

    @Test fun the_circle_key_converges_along_a_chain_of_meetings_and_outsiders_cannot_join() {
        val ds = List(5) { Dev("d$it") }; for (i in 0 until 4) meetOffline(ds[i], ds[i + 1])
        assertEquals(1, ds.map { hex(it.m.circleKey) }.toSet().size)
        val stranger = Dev("x"); assertNotEquals(hex(stranger.m.circleKey), hex(ds[0].m.circleKey))
        val e = MeshEnvelope.build(MeshCircle(stranger.m.circleKey), rnd.generateSeed(100), now / 60_000 + 60)
        assertFalse(MeshEnvelope.verify(MeshEnvelope.parse(e)!!, MeshCircle(ds[0].m.circleKey)))
    }

    @Test fun a_message_crosses_two_relays_arrives_once_and_relays_cannot_read_it() {
        val (a, b) = world("a", "b").let { it[0] to it[1] }
        val r1 = Dev("r1").also { it.joinMesh({ now }) }; val r2 = Dev("r2").also { it.joinMesh({ now }) }
        // relays are circle members (same key) but know nobody: they can carry, never read
        val key = a.m.circleKey; for (r in listOf(r1, r2)) { r.node = MeshNode(MeshCircle(key), EncryptedMemoryStore(rnd.generateSeed(32)), { now }, { r.m.receiveCiphertext(it) }) }
        a.m.sendText(a.contactOf(b), "через два ретранслятора")                          // no server: the only path is the mesh
        encounter(a.node, r1.node); encounter(r1.node, r2.node)
        assertEquals(emptyList(), r1.storage.messages(1)); assertEquals(emptyList(), r2.storage.messages(1))
        encounter(r2.node, b.node)
        assertEquals(listOf<String?>("через два ретранслятора"), texts(b, a))
        encounter(r2.node, b.node); encounter(r1.node, b.node); encounter(a.node, b.node)   // meeting again changes nothing
        assertEquals(1, texts(b, a).size)
    }

    @Test fun relays_that_forwarded_the_message_have_nothing_left_and_the_content_is_not_in_their_memory() {
        val (a, b) = world("a", "b").let { it[0] to it[1] }
        val key = a.m.circleKey; val relays = List(3) { Dev("r$it") }
        relays.forEach { r -> r.node = MeshNode(MeshCircle(key), EncryptedMemoryStore(rnd.generateSeed(32)), { now }, { false }, Limits(fanout = 2)) }
        a.node = MeshNode(MeshCircle(key), EncryptedMemoryStore(rnd.generateSeed(32)), { now }, { a.m.receiveCiphertext(it) }, Limits(fanout = 2)); a.m.meshOut = { a.node.inject(it) }
        val marker = "СЕКРЕТ-" + rnd.nextInt(); a.m.sendText(a.contactOf(b), marker)
        encounter(a.node, relays[0].node); encounter(a.node, relays[1].node)             // a handed it to two neighbours: it forgets
        assertEquals(0, a.node.held())
        encounter(relays[0].node, relays[2].node); encounter(relays[0].node, b.node)
        assertEquals(0, relays[0].node.held()); assertEquals(0, relays[0].node.stored())
        for (r in relays) assertFalse(deepContains(r.node, marker.toByteArray(), marker))      // relays: nothing of the content anywhere in memory
        assertEquals(0, a.node.stored()); assertFalse(a.node.snapshot().contains(marker))     // the origin's mesh buffer is empty too (its own chat history is separate)
        assertFalse(a.node.snapshot().contains("peer-"))
    }

    @Test fun the_same_message_over_server_and_mesh_is_delivered_only_once() {
        val (a, b) = world("a", "b").let { it[0] to it[1] }
        var serverEnvelope: ByteArray? = null
        a.m.outbound = Messenger.Outbound { _, env -> serverEnvelope = env }              // the server path (captured instead of sent)
        a.m.sendText(a.contactOf(b), "по двум путям")
        assertNotNull(serverEnvelope); assertTrue(b.m.receive(serverEnvelope!!))             // arrives through the server first
        encounter(a.node, b.node)                                                            // and again through the mesh
        assertEquals(listOf<String?>("по двум путям"), texts(b, a))
    }

    @Test fun a_file_crosses_a_lossy_mesh_missing_chunks_are_requested_and_resent() {
        val (a, b) = world("a", "b").let { it[0] to it[1] }
        val data = ByteArray(9000) { (it * 31).toByte() }
        // b must be able to answer too: it is in the same mesh
        assertTrue(a.m.sendFileMesh(a.contactOf(b), data, "photo.jpg", false))
        var rounds = 0
        while (b.storage.messages(b.contactOf(a).id).none { it.hasFile } && rounds++ < 40) {
            var seen = 0
            // round 1: the 2nd and 4th envelope are certainly lost; later rounds: a third of the envelopes at random
            encounter(a.node, b.node, lose = { m -> m is MeshMsg.Env && (if (rounds == 1) (++seen).let { it == 2 || it == 4 } else rnd.nextInt(100) < 35) })
            b.m.requestMissingChunks()                                                                  // b asks for what is still missing
            now += 60_000
        }
        val file = b.storage.messages(b.contactOf(a).id).firstOrNull { it.hasFile }
        assertNotNull(file, "file did not arrive after $rounds rounds"); assertEquals("photo.jpg", file.fileName)
        assertContentEquals(data, b.storage.messageFile(file.id))
        assertTrue(rounds > 1, "loss was real")
    }

    @Test fun only_the_intended_receiver_can_ask_for_chunks() {
        val (a, b, c) = world("a", "b", "c"); meetOffline(a, c)
        // c can talk to a as well (a session in that direction too), so the request really reaches a's code
        noc.crypto.Conversation(c.m.me, org.signal.libsignal.protocol.SignalProtocolAddress(hex(a.m.signer.publicKey), 1)).startFrom(a.m.me.bundle, a.m.me.oneTimeKeys().first())
        val sentByA = ArrayList<ByteArray>(); val inject = a.m.meshOut!!
        a.m.meshOut = { ct -> sentByA.add(ct); inject(ct) }
        a.m.sendFileMesh(a.contactOf(b), ByteArray(6000) { it.toByte() }, "secret.bin", false)
        val total = sentByA.size; assertTrue(total >= 4)                                           // manifest + chunks
        // learn the file id the way the legitimate receiver does: by decrypting the manifest as b
        val manifest = noc.crypto.Conversation(b.m.me, org.signal.libsignal.protocol.SignalProtocolAddress(hex(a.m.signer.publicKey), 1)).openRaw(sentByA[0])
        val fileId = noc.crypto.FileManifest.parse(manifest.payload).fileId
        fun need(from: Dev, idx: Int): ByteArray {
            val payload = java.nio.ByteBuffer.allocate(16 + 2 + 4).put(fileId).putShort(1).putInt(idx).array()
            return noc.crypto.Conversation(from.m.me, org.signal.libsignal.protocol.SignalProtocolAddress(hex(a.m.signer.publicKey), 1))
                .sealRaw(noc.crypto.Inner(noc.crypto.Kind.FILE_NEED, from.m.signer.publicKey, 1, 0, payload))
        }
        // c is a contact of a, but the file was not for c: its request is ignored
        a.m.receiveCiphertext(need(c, 0)); assertEquals(total, sentByA.size, "a re-sent a chunk to the wrong person")
        // control: the real receiver gets the chunk re-sent
        a.m.receiveCiphertext(need(b, 0)); assertEquals(total + 1, sentByA.size, "the legitimate request was not served")
    }

    @Test fun a_long_chain_delivers_within_the_hop_limit_and_stops_beyond_it() {
        val devs = world("a", "b"); val (a, b) = devs
        val key = a.m.circleKey
        val chain = List(5) { MeshNode(MeshCircle(key), EncryptedMemoryStore(rnd.generateSeed(32)), { now }, { false }, Limits(maxHops = 6, fanout = 5)) }
        a.node = MeshNode(MeshCircle(key), EncryptedMemoryStore(rnd.generateSeed(32)), { now }, { a.m.receiveCiphertext(it) }, Limits(fanout = 5)); a.m.meshOut = { a.node.inject(it) }
        a.m.sendText(a.contactOf(b), "через цепочку")
        encounter(a.node, chain[0]); for (i in 0 until 4) encounter(chain[i], chain[i + 1]); encounter(chain[4], b.node)
        assertEquals(listOf<String?>("через цепочку"), texts(b, a))                        // 5 relays between: 6 hops in total
    }

    @Test fun one_hundred_messages_over_a_random_mesh_arrive_exactly_once_each_with_bounded_buffers() {
        val ds = world("a", "b", "c", "d", "e", "f").toList()
        val limits = Limits(maxEntries = 24, maxBytes = 24L * MESH_ENVELOPE, fanout = 3)
        ds.forEach { it.joinMesh({ now }, limits) }
        val a = ds[0]; val f = ds[5]; meetOffline(a, f)
        val sent = (1..100).map { "msg-$it" }
        sent.forEachIndexed { i, t ->
            a.m.sendText(a.contactOf(f), t)
            repeat(8) { val x = ds[rnd.nextInt(6)]; val y = ds[rnd.nextInt(6)]; if (x !== y) encounter(x.node, y.node); now += 1000 }
            ds.forEach { assertTrue(it.node.held() <= 24) }
        }
        repeat(300) { val x = ds[rnd.nextInt(6)]; val y = ds[rnd.nextInt(6)]; if (x !== y) encounter(x.node, y.node); now += 1000 }
        val got = texts(f, a).filterNotNull()
        assertEquals(got.size, got.toSet().size, "a message was delivered twice")
        assertTrue(got.size >= 40, "only ${got.size} of 100 arrived")                         // bounded buffers may drop under load; delivery must still be substantial
        assertTrue(got.all { it in sent })
    }
}
