package noc.crypto

import org.signal.libsignal.protocol.SignalProtocolAddress
import org.signal.libsignal.protocol.UntrustedIdentityException
import java.io.File
import java.security.Signature
import java.security.SecureRandom
import kotlin.test.*

private val rnd = SecureRandom()
private fun key32() = ByteArray(32).also { rnd.nextBytes(it) }

/** alice and bob have met in person: both pinned each other's identity from the QR. */
class Pair2 {
    val alice = LocalIdentity.create(); val bob = LocalIdentity.create()
    val aliceKey = key32(); val bobKey = key32()
    val aAddr = SignalProtocolAddress("alice", 1); val bAddr = SignalProtocolAddress("bob", 1)
    val aliceToBob = Conversation(alice, bAddr); val bobToAlice = Conversation(bob, aAddr)
    init {
        alice.store.pin(bAddr, bob.identityKey); bob.store.pin(aAddr, alice.identityKey)
        // what the server would hand out: the long-term blob (parsed back) plus one one-time key
        aliceToBob.startFrom(LongTermBundle.parse(bob.bundle.serialize()), OneTime.parse(bob.oneTimeKeys()[0].serialize()))
    }
    fun text(from: ByteArray, s: String, ttl: Int = 0) = Inner(Kind.TEXT, from, 1_700_000_000_000, ttl, s.toByteArray())
}

class SessionTest {
    @Test fun pqxdh_bundle_carries_kyber1024_and_roundtrip_both_ways() {
        val p = Pair2()
        assertTrue(p.bob.bundle.kyberKey.serialize().size > 1500)       // ML-KEM-1024 public key
        val e1 = p.aliceToBob.seal(p.text(p.aliceKey, "привет"))
        assertEquals("привет", String(p.bobToAlice.open(e1).payload))
        val e2 = p.bobToAlice.seal(p.text(p.bobKey, "hi"))
        assertEquals("hi", String(p.aliceToBob.open(e2).payload))
    }

    @Test fun key_changes_on_every_message() {
        val p = Pair2()
        p.bobToAlice.open(p.aliceToBob.seal(p.text(p.aliceKey, "a")))
        val reply = p.bobToAlice.seal(p.text(p.bobKey, "b")); p.aliceToBob.open(reply)
        val same = p.text(p.aliceKey, "same")
        val c = (1..3).map { p.aliceToBob.seal(same) }
        assertEquals(3, c.map { it.toList() }.toSet().size)             // identical plaintext -> different ciphertext
        c.forEach { assertEquals("same", String(p.bobToAlice.open(it).payload)) }
    }

    @Test fun inner_metadata_roundtrips() {
        val p = Pair2()
        val got = p.bobToAlice.open(p.aliceToBob.seal(p.text(p.aliceKey, "x", ttl = 60)))
        assertContentEquals(p.aliceKey, got.senderDeviceKey); assertEquals(60, got.expireAfterS); assertEquals(Kind.TEXT, got.kind)
    }

    @Test fun replay_is_rejected() {
        val p = Pair2()
        val e = p.aliceToBob.seal(p.text(p.aliceKey, "once"))
        p.bobToAlice.open(e)
        assertFails { p.bobToAlice.open(e) }
    }

    @Test fun unknown_contact_cannot_start_session() {
        val a = LocalIdentity.create(); val b = LocalIdentity.create()
        val c = Conversation(a, SignalProtocolAddress("bob", 1))
        assertFailsWith<UntrustedIdentityException> { c.startFrom(b.bundle, null) }
    }

    @Test fun changed_key_is_refused_until_user_accepts() {
        val p = Pair2()
        p.bobToAlice.open(p.aliceToBob.seal(p.text(p.aliceKey, "hello")))     // normal chat with the real bob works
        // an impostor with a different identity key pretends to be "bob" and writes to alice
        val impostor = LocalIdentity.create()
        val aliceAddr = SignalProtocolAddress("alice", 1)
        impostor.store.pin(aliceAddr, p.alice.identityKey)
        val fake = Conversation(impostor, aliceAddr)
        fake.startFrom(p.alice.bundle, null)
        val forged = fake.seal(p.text(key32(), "I am bob"))
        val aliceSide = Conversation(p.alice, p.bAddr)
        assertFails { aliceSide.open(forged) }                                 // refused: key differs from the pinned one
        p.alice.store.acceptKeyChange(p.bAddr, impostor.identityKey)           // only after an explicit user decision
        assertEquals("I am bob", String(aliceSide.open(forged).payload))
    }

    @Test fun safety_number_same_on_both_sides_and_changes_with_key() {
        val p = Pair2()
        val a = SafetyNumber.of("alice".toByteArray(), p.alice.identityKey, "bob".toByteArray(), p.bob.identityKey)
        val b = SafetyNumber.of("bob".toByteArray(), p.bob.identityKey, "alice".toByteArray(), p.alice.identityKey)
        assertEquals(a, b); assertEquals(60, a.filter { it.isDigit() }.length)
        val c = SafetyNumber.of("alice".toByteArray(), p.alice.identityKey, "bob".toByteArray(), LocalIdentity.create().identityKey)
        assertNotEquals(a, c)
    }
}

class EnvelopeTest {
    @Test fun every_envelope_has_the_same_length_for_any_message_size() {
        val p = Pair2()
        val sizes = listOf(0, 1, 100, 1000, 5000, 11_500)
        val lens = sizes.map { n -> p.aliceToBob.seal(Inner(Kind.TEXT, p.aliceKey, 0, 0, ByteArray(n))).size }
        assertEquals(setOf(ENVELOPE_SIZE), lens.toSet())
    }

    @Test fun padding_is_random_not_zero() {
        val p = Pair2()
        val e = p.aliceToBob.seal(p.text(p.aliceKey, "x"))
        assertTrue(e.takeLast(2000).distinct().size > 100)
    }

    @Test fun tampering_and_wrong_sizes_are_rejected() {
        val p = Pair2()
        val e = p.aliceToBob.seal(p.text(p.aliceKey, "x"))
        assertFailsWith<MalformedException> { Envelope.unpack(e.copyOf(100)) }
        assertFailsWith<MalformedException> { Envelope.unpack(ByteArray(ENVELOPE_SIZE)) }
        val bad = e.copyOf(); bad[40] = (bad[40].toInt() xor 1).toByte()
        assertFails { p.bobToAlice.open(bad) }
    }

    @Test fun too_large_ciphertext_is_refused() {
        assertFailsWith<MalformedException> { Envelope.pack(ByteArray(ENVELOPE_SIZE)) }
    }
}

class FileTest {
    private fun data(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }

    @Test fun roundtrip_over_real_sessions_including_worst_case_first_message() {
        val p = Pair2()
        val file = data(50_000)
        val (m, chunks) = FileCrypto.encrypt(file, "memo.ogg", voice = true)
        // manifest goes first (this is the PreKey message: the largest envelope), chunks follow
        val env = mutableListOf(p.aliceToBob.seal(Inner(Kind.FILE_MANIFEST, p.aliceKey, 0, 0, m.serialize())))
        chunks.forEachIndexed { i, c ->
            env += p.aliceToBob.seal(Inner(Kind.FILE_CHUNK, p.aliceKey, 0, 0, java.nio.ByteBuffer.allocate(4 + c.size).putInt(i).put(c).array()))
        }
        assertEquals(setOf(ENVELOPE_SIZE), env.map { it.size }.toSet())
        val first = p.bobToAlice.open(env[0]); assertEquals(Kind.FILE_MANIFEST, first.kind)
        val m2 = FileManifest.parse(first.payload); assertTrue(m2.voice); assertEquals("memo.ogg", m2.name)
        val asm = FileAssembler(m2)
        env.drop(1).reversed().forEach { e ->          // out of order
            val msg = p.bobToAlice.open(e); val b = java.nio.ByteBuffer.wrap(msg.payload)
            assertTrue(asm.accept(b.getInt(), ByteArray(b.remaining()).also { b.get(it) }))
        }
        assertContentEquals(file, asm.finish())
    }

    @Test fun missing_chunks_are_reported_and_can_be_resent() {
        val (m, chunks) = FileCrypto.encrypt(data(40_000)); val a = FileAssembler(m)
        a.accept(0, chunks[0]); a.accept(2, chunks[2])
        assertEquals(listOf(1, 3), a.missing()); assertFailsWith<MalformedException> { a.finish() }
        a.accept(1, chunks[1]); a.accept(3, chunks[3]); a.finish()
    }

    @Test fun corrupted_swapped_or_foreign_chunks_rejected() {
        val (m, chunks) = FileCrypto.encrypt(data(30_000)); val a = FileAssembler(m)
        val bad = chunks[0].copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        assertFalse(a.accept(0, bad))
        assertFalse(a.accept(1, chunks[0]))                      // right bytes, wrong slot
        val (_, other) = FileCrypto.encrypt(data(30_000)); assertFalse(a.accept(0, other[0]))
        assertFalse(a.accept(99, chunks[0]))
        assertEquals(listOf(0, 1, 2), a.missing())
    }

    @Test fun whole_file_checksum_is_enforced() {
        val (m, chunks) = FileCrypto.encrypt(data(5_000))
        val forged = FileManifest(m.fileId, m.key, m.size, m.count, m.chunkHashes, ByteArray(32), m.voice, m.name)
        val a = FileAssembler(forged); a.accept(0, chunks[0])
        assertFailsWith<MalformedException> { a.finish() }
    }

    @Test fun empty_file_works_and_keys_are_unique_per_file() {
        val (m, c) = FileCrypto.encrypt(ByteArray(0)); val a = FileAssembler(m); assertTrue(a.accept(0, c[0])); assertEquals(0, a.finish().size)
        assertFalse(FileCrypto.encrypt(data(10)).first.key.contentEquals(FileCrypto.encrypt(data(10)).first.key))
    }

    @Test fun malformed_manifest_is_rejected() {
        assertFailsWith<MalformedException> { FileManifest.parse(ByteArray(10)) }
    }
}

class InviteTest {
    private val id = LocalIdentity.create()

    @Test fun roundtrip_expiry_and_single_use() {
        val book = InviteBook(ttlS = 300)
        val inv = book.issue(id.identityKey, key32(), ByteArray(16), nowS = 1000)
        val dec = Invite.decode(inv.encode(), nowS = 1100)
        assertEquals(id.identityKey, dec.identity)
        assertTrue(book.redeem(dec.nonce, 1100)); assertFalse(book.redeem(dec.nonce, 1100))
        assertFailsWith<MalformedException> { Invite.decode(inv.encode(), nowS = 2000) }
        val late = book.issue(id.identityKey, key32(), ByteArray(16), nowS = 1000)
        assertFalse(book.redeem(late.nonce, 2000))
    }

    @Test fun garbage_is_rejected() {
        listOf("", "AAAA", "!!!", "x".repeat(500)).forEach { assertFailsWith<MalformedException> { Invite.decode(it, 0) } }
        assertFalse(InviteBook().redeem(ByteArray(16), 0))
    }
}

class AuthTest {
    @Test fun signature_verifies_with_jdk_and_matches_server_vector() {
        val s = SoftwareSigner.generate()
        val body = """{"role":"user"}""".toByteArray()
        val h = DeviceAuth.headers(s, "PUT", "/v1/admin/users/abc", body, 1_700_000_000, ByteArray(16) { it.toByte() })
        val spki = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + s.publicKey
        val pub = java.security.KeyFactory.getInstance("Ed25519").generatePublic(java.security.spec.X509EncodedKeySpec(spki))
        val sig = java.util.Base64.getUrlDecoder().decode(h.getValue("x-sig"))
        val msg = DeviceAuth.message("PUT", "/v1/admin/users/abc", h.getValue("x-ts"), h.getValue("x-nonce"), body)
        assertTrue(Signature.getInstance("Ed25519").run { initVerify(pub); update(msg); verify(sig) })
        // vector for the Python server test (protocol/vectors/auth.json)
        val out = System.getProperty("vector.out")
        if (out != null) File(out).writeText("""{"method":"PUT","path":"/v1/admin/users/abc","body":"{\"role\":\"user\"}","headers":{${h.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" }}}}""")
    }
}
