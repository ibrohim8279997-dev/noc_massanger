package noc.mesh

import noc.client.*
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.*

private val rnd = SecureRandom()

class BulkFileTest {
    private var now = 3_000_000_000L
    private fun pair(limits: Limits = Limits(maxEntries = 64, maxBytes = 64L * MESH_ENVELOPE)): Pair<Dev, Dev> {
        val a = Dev("a"); val b = Dev("b"); meetOffline(a, b)
        a.joinMesh({ now }, limits); b.joinMesh({ now }, limits)
        a.m.meshFileLimit = 20 * 1024 * 1024; b.m.meshFileLimit = 20 * 1024 * 1024
        return a to b
    }

    @Test fun a_file_far_larger_than_the_relay_buffer_arrives_in_windows_with_the_buffer_never_exceeded() {
        val (a, b) = pair(); val data = ByteArray(700_000).also { rnd.nextBytes(it) }       // ~390 chunks, buffer holds 64
        val injected = AtomicInteger(0); val send = a.m.meshOut!!; a.m.meshOut = { ct -> injected.incrementAndGet(); send(ct) }
        assertTrue(a.m.sendFileMesh(a.contactOf(b), data, "big.bin", false))
        assertTrue(injected.get() <= 33, "only manifest + first window may go out at once, was ${injected.get()}")
        var peak = 0; var rounds = 0; var needs = 0
        while (b.storage.messages(b.contactOf(a).id).none { it.hasFile } && rounds++ < 400) {
            encounter(a.node, b.node)
            needs += b.m.requestMissingChunks()
            peak = maxOf(peak, a.node.held(), b.node.held())
        }
        val f = b.storage.messages(b.contactOf(a).id).firstOrNull { it.hasFile }
        assertNotNull(f, "not delivered after $rounds rounds"); assertContentEquals(data, b.storage.messageFile(f.id))
        assertTrue(peak <= 64, "buffer exceeded: $peak"); assertTrue(needs >= 10, "later windows must come from requests, got $needs")
        assertTrue(injected.get() in 390..470, "no flooding: ${injected.get()} envelopes for ~390 chunks")
    }

    @Test fun lost_chunks_are_asked_for_again_after_the_retry_time() {
        val (a, b) = pair(); b.m.needRetryMs = 0; val data = ByteArray(150_000).also { rnd.nextBytes(it) }
        a.m.sendFileMesh(a.contactOf(b), data, "x.bin", false)
        var rounds = 0
        while (b.storage.messages(b.contactOf(a).id).none { it.hasFile } && rounds++ < 600) {
            encounter(a.node, b.node, lose = { m -> m is MeshMsg.Env && rnd.nextInt(100) < 40 })     // 40% of envelopes vanish, both directions
            b.m.requestMissingChunks(); now += 1000
        }
        assertContentEquals(data, b.storage.messageFile(b.storage.messages(b.contactOf(a).id).first { it.hasFile }.id))
    }

    @Test fun nothing_is_requested_twice_inside_the_retry_window() {
        val (a, b) = pair(); val data = ByteArray(200_000).also { rnd.nextBytes(it) }
        a.m.sendFileMesh(a.contactOf(b), data, "y.bin", false); encounter(a.node, b.node)       // manifest + first window arrive
        val first = b.m.requestMissingChunks(); val second = b.m.requestMissingChunks()
        assertTrue(first >= 1, "the next window is requested"); assertEquals(0, second, "the same chunks are not requested again within the retry time")
    }

    @Test fun a_file_over_the_mesh_limit_is_refused_without_side_effects() {
        val (a, b) = pair(); a.m.meshFileLimit = 100_000
        assertFalse(a.m.sendFileMesh(a.contactOf(b), ByteArray(100_001), "z", false)); assertEquals(0, a.node.held())
        assertTrue(a.m.sendFileMesh(a.contactOf(b), ByteArray(100_000) { 1 }, "z", false))
    }

    @Test fun a_stranger_cannot_make_the_sender_resend_chunks() {
        // covered in MeshSimTest.only_the_intended_receiver_can_ask_for_chunks; here: requests for unknown files are ignored
        val (a, b) = pair(); a.m.sendFileMesh(a.contactOf(b), ByteArray(80_000), "q", false); val held = a.node.held()
        val payload = java.nio.ByteBuffer.allocate(16 + 2 + 4).put(ByteArray(16) { 9 }).putShort(1).putInt(0).array()
        val ct = noc.crypto.Conversation(b.m.me, org.signal.libsignal.protocol.SignalProtocolAddress(hex(a.m.signer.publicKey), 1))
        // b has no session in that direction yet: first make it exist by letting b receive a's manifest
        encounter(a.node, b.node)
        val need = noc.crypto.Conversation(b.m.me, org.signal.libsignal.protocol.SignalProtocolAddress(hex(a.m.signer.publicKey), 1)).sealRaw(noc.crypto.Inner(noc.crypto.Kind.FILE_NEED, b.m.signer.publicKey, 1, 0, payload))
        a.m.receiveCiphertext(need)
        assertTrue(a.node.held() <= held)                                            // unknown file id: nothing was re-sent
        assertNotNull(ct)
    }
}

class SessionTest {
    private val circle = MeshCircle(rnd.generateSeed(32))
    private var now = 1_000_000_000L
    private fun node(c: MeshCircle = circle, deliver: (ByteArray) -> Boolean = { false }) = MeshNode(c, EncryptedMemoryStore(rnd.generateSeed(32)), { now }, deliver)

    /** wires two sessions together in memory, frame by frame, preserving order */
    private class Wire(val a: MeshSession, val b: MeshSession)
    private fun wire(na: MeshNode, ca: MeshCircle, nb: MeshNode, cb: MeshCircle, fragment: Boolean, tap: (ByteArray) -> Unit = {}): Pair<MeshSession, MeshSession> {
        lateinit var sa: MeshSession; lateinit var sb: MeshSession
        val q = ArrayDeque<Pair<Boolean, ByteArray>>()                  // (toB?, frame)
        sa = MeshSession(na, ca, true, fragment, { q.add(true to it); tap(it) }); sb = MeshSession(nb, cb, false, fragment, { q.add(false to it); tap(it) })
        sa.start(); sb.start()
        var guard = 0
        while (q.isNotEmpty() && guard++ < 100_000) { val (toB, f) = q.removeFirst(); if (toB) sb.onFrame(f) else sa.onFrame(f) }
        return sa to sb
    }

    @Test fun members_authenticate_each_other_and_exchange_envelopes_whole_or_in_fragments() {
        for (fragment in listOf(false, true)) {
            val got = ArrayList<ByteArray>(); val a = node(); val b = node(deliver = { got.add(it); true }); a.inject(rnd.generateSeed(300))
            val (sa, sb) = wire(a, circle, b, circle, fragment)
            assertTrue(sa.authenticated && sb.authenticated); assertEquals(1, got.size, "fragment=$fragment")
        }
    }

    @Test fun a_stranger_with_another_circle_key_gets_nothing_and_is_hung_up_on() {
        val other = MeshCircle(rnd.generateSeed(32)); val a = node(); a.inject(rnd.generateSeed(300)); val frames = ArrayList<ByteArray>()
        val s = node(other)
        val (sa, ss) = wire(a, circle, s, other, false) { frames.add(it) }
        assertFalse(sa.authenticated); assertFalse(ss.authenticated); assertTrue(sa.closed || ss.closed)
        assertTrue(frames.none { it[0] == 1.toByte() || it[0] == 3.toByte() && it.size > 100 }, "no hello/envelope went out before authentication")
        assertEquals(0, s.held())
    }

    @Test fun a_reflected_proof_does_not_authenticate() {
        val a = node(); val out = ArrayList<ByteArray>()
        val sa = MeshSession(a, circle, true, false, { out.add(it) }); sa.start()
        val myNonceFrame = out[0]                                                   // the attacker echoes my own nonce and my own proof back to me
        sa.onFrame(myNonceFrame)                                                    // "peer's" nonce = my nonce
        val myProof = out[1]; sa.onFrame(myProof)                                   // "peer's" proof = my proof
        assertFalse(sa.authenticated); assertTrue(sa.closed)
    }

    @Test fun data_before_authentication_and_garbage_are_refused() {
        val a = node(); val out = ArrayList<ByteArray>(); val s = MeshSession(a, circle, false, false, { out.add(it) })
        s.onFrame(MeshMsg.Hello(listOf(1L)).encode()); assertTrue(s.closed); assertTrue(out.isEmpty() || out.none { it[0] == 2.toByte() })
        val s2 = MeshSession(a, circle, false, false, { }); s2.onFrame(ByteArray(0)); s2.onFrame(ByteArray(100_000)); s2.onFrame(byteArrayOf(0xA1.toByte(), 1, 2, 3)); assertFalse(s2.authenticated)
    }

    @Test fun in_bluetooth_mode_no_frame_is_larger_than_a_small_radio_packet_even_with_many_envelopes_carried() {
        val frames = ArrayList<ByteArray>(); val a = node(); val b = node(deliver = { true })
        repeat(60) { a.inject(rnd.generateSeed(200)) }                              // 60 envelopes to offer: the hello list is long
        wire(a, circle, b, circle, true) { frames.add(it) }
        assertTrue(frames.size > 100); assertTrue(frames.all { it.size <= 194 }, "largest frame: ${frames.maxOf { it.size }}")   // BLE allows ~240
    }

    @Test fun frame_stream_roundtrip_and_oversize_refusal() {
        val bo = java.io.ByteArrayOutputStream(); FrameStream.write(bo, byteArrayOf(1, 2, 3)); FrameStream.write(bo, ByteArray(4097))
        val bi = java.io.ByteArrayInputStream(bo.toByteArray())
        assertContentEquals(byteArrayOf(1, 2, 3), FrameStream.read(bi)); assertEquals(4097, FrameStream.read(bi).size)
        assertFailsWith<java.io.IOException> { FrameStream.read(java.io.ByteArrayInputStream(java.nio.ByteBuffer.allocate(8).putInt(10_000_000).array())) }
        assertFailsWith<java.io.EOFException> { FrameStream.read(java.io.ByteArrayInputStream(byteArrayOf(0, 0, 0, 9, 1))) }
    }
}

/** The Wi-Fi Direct data path (a TCP socket between two phones) with the real session layer, real crypto, real concurrency. */
class TcpLinkTest {
    @Test fun one_megabyte_file_over_a_tcp_link_with_authentication_both_directions_and_no_deadlock() {
        var clockMs = 4_000_000_000L
        val a = Dev("a"); val b = Dev("b"); meetOffline(a, b)
        val big = Limits(maxEntries = 128, maxBytes = 128L * MESH_ENVELOPE)
        a.joinMesh({ clockMs }, big); b.joinMesh({ clockMs }, big)
        a.m.meshFileLimit = 20 * 1024 * 1024; b.m.needRetryMs = 2000
        val server = ServerSocket(0); val stop = AtomicBoolean(false)
        fun run(sock: Socket, dev: Dev, initiator: Boolean): MeshSession {
            val out = sock.getOutputStream()
            val s = MeshSession(dev.node, MeshCircle(dev.m.circleKey), initiator, fragment = false, send = { synchronized(out) { FrameStream.write(out, it) } })
            thread(isDaemon = true) { try { s.start(); while (!stop.get()) s.onFrame(FrameStream.read(sock.getInputStream())) } catch (e: Exception) { } }
            return s
        }
        val acceptor = thread { /* placeholder to keep structure simple */ }
        val clientSock = Socket("127.0.0.1", server.localPort); val serverSock = server.accept()
        val sa = run(clientSock, a, true); val sb = run(serverSock, b, false)
        val data = ByteArray(1_000_000).also { rnd.nextBytes(it) }
        val before = a.node.held()
        assertTrue(a.m.sendFileMesh(a.contactOf(b), data, "movie.bin", false))
        // both sides keep working in separate threads, hammering the locks from every direction
        val pumps = listOf(a to sa, b to sb).map { (d, s) -> thread(isDaemon = true) { while (!stop.get()) { try { s.offer(); d.m.requestMissingChunks() } catch (e: Exception) { }; Thread.sleep(15) } } }
        val chat = thread(isDaemon = true) { var i = 0; while (!stop.get()) { try { b.m.sendText(b.contactOf(a), "ping ${i++}") } catch (e: Exception) { }; Thread.sleep(40) } }
        try {
            waitFor(90_000) { b.storage.messages(b.contactOf(a).id).any { it.hasFile } }
        } finally { stop.set(true); runCatching { clientSock.close(); serverSock.close(); server.close() } }
        val f = b.storage.messages(b.contactOf(a).id).first { it.hasFile }
        assertContentEquals(data, b.storage.messageFile(f.id))
        assertTrue(sa.authenticated && sb.authenticated)
        assertTrue(a.storage.messages(a.contactOf(b).id).any { !it.outgoing && it.text?.startsWith("ping") == true }, "messages flowed the other way at the same time")
        assertTrue(before == 0 && a.node.held() <= 128 && b.node.held() <= 128)
        assertNotNull(acceptor)
    }
}

private fun waitFor(ms: Long, cond: () -> Boolean) { val end = System.currentTimeMillis() + ms; while (!cond()) { if (System.currentTimeMillis() > end) error("timeout"); Thread.sleep(50) } }
