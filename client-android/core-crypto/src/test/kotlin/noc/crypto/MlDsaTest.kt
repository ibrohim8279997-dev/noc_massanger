package noc.crypto

import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.pqc.crypto.mldsa.*
import java.io.File
import java.security.SecureRandom
import kotlin.test.*

class MlDsaTest {
    private val rnd = SecureRandom()
    private fun msg(n: Int = 120) = ByteArray(n).also { rnd.nextBytes(it) }

    @Test fun keys_and_signature_have_the_fips_204_sizes_and_verify() {
        val (pk, sk) = MlDsa65.keyPair(); val m = msg(); val sig = MlDsa65.sign(sk, m)
        assertEquals(1952, pk.size); assertEquals(4032, sk.size); assertTrue(sig.size in 1..3309)
        assertTrue(MlDsa65.verify(pk, m, sig))
    }

    @Test fun any_change_to_message_signature_or_key_is_rejected() {
        val (pk, sk) = MlDsa65.keyPair(); val m = msg(); val sig = MlDsa65.sign(sk, m)
        assertFalse(MlDsa65.verify(pk, m + 1, sig)); assertFalse(MlDsa65.verify(MlDsa65.keyPair().first, m, sig))
        for (pos in listOf(0, 17, sig.size / 2, sig.size - 1)) assertFalse(MlDsa65.verify(pk, m, sig.copyOf().also { it[pos] = (it[pos].toInt() xor 1).toByte() }), "bit at $pos")
        assertFalse(MlDsa65.verify(pk, m, sig.copyOf(sig.size - 1))); assertFalse(MlDsa65.verify(pk, m, ByteArray(0)))
        assertFalse(MlDsa65.verify(pk.copyOf(10), m, sig))
    }

    @Test fun wrong_sized_secret_key_is_refused_not_crashed() {
        assertFailsWith<IllegalArgumentException> { MlDsa65.sign(ByteArray(10), msg()) }
    }

    @Test fun independent_implementation_bouncycastle_accepts_a_liboqs_signature() {
        val (pk, sk) = MlDsa65.keyPair(); val m = msg(300); val sig = MlDsa65.sign(sk, m)
        fun bcVerify(message: ByteArray) = MLDSASigner().run { init(false, MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, pk)); update(message, 0, message.size); verifySignature(sig) }
        assertTrue(bcVerify(m)); assertFalse(bcVerify(m + 1))
    }

    @Test fun and_liboqs_accepts_a_bouncycastle_signature_with_liboqs_generated_keys() {
        val (pk, sk) = MlDsa65.keyPair(); val m = msg(300)
        val signer = MLDSASigner().apply { init(true, ParametersWithRandom(MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_65, sk), rnd)) }
        signer.update(m, 0, m.size); val sig = signer.generateSignature()
        assertTrue(MlDsa65.verify(pk, m, sig))
    }

    @Test fun hybrid_signer_adds_the_pq_header_and_it_verifies_over_the_same_message() {
        val a = HybridSigner.generate()
        val h = DeviceAuth.headers(a, "PUT", "/v1/admin/users/x", "{}".toByteArray(), 1_700_000_000, ByteArray(16) { 3 })
        val msg = DeviceAuth.message("PUT", "/v1/admin/users/x", h.getValue("x-ts"), h.getValue("x-nonce"), "{}".toByteArray())
        val pq = java.util.Base64.getUrlDecoder().decode(h.getValue("x-pq-sig"))
        assertTrue(MlDsa65.verify(a.pqPublic, "NOC1-PQ\n".toByteArray() + msg, pq))
        assertFalse(MlDsa65.verify(a.pqPublic, msg, pq))                                           // domain separated: not valid for the plain message
        // ordinary users get no pq header
        assertFalse(DeviceAuth.headers(SeedSigner(SeedSigner.newSeed()), "GET", "/x", ByteArray(0), 1, ByteArray(16)).containsKey("x-pq-sig"))
    }

    @Test fun writes_an_interop_vector_for_the_python_server() {
        val out = System.getProperty("mldsa.vector.out") ?: return
        val (pk, sk) = MlDsa65.keyPair(); val m = "NOC1-PQ\nvector".toByteArray(); val sig = MlDsa65.sign(sk, m)
        val b = java.util.Base64.getEncoder()
        File(out).writeText("""{"pk":"${b.encodeToString(pk)}","msg":"${b.encodeToString(m)}","sig":"${b.encodeToString(sig)}"}""")
    }
}
