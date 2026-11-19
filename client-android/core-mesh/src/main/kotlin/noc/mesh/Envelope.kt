package noc.mesh

import noc.crypto.Ed25519Verify
import noc.crypto.SeedSigner
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

const val MESH_ENVELOPE = 4096

/** Shared secret of the small circle. Proves "sent by someone in the circle" to relays without saying who. */
class MeshCircle(val key: ByteArray) {
    init { require(key.size == 32) }
    private fun hmac(label: String, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); update(label.toByteArray()); doFinal(data) }
    fun tag(data: ByteArray): ByteArray = hmac("NOC-MESH-TAG", data).copyOf(16)
    fun adSlotUuid(slot: Long): ByteArray = hmac("NOC-MESH-ADV", ByteBuffer.allocate(8).putLong(slot).array()).copyOf(16)
}

/**
 * Fixed 4096-byte envelope. Everything in the header is random per message or coarse:
 *  version | id (random, one-time) | expiry (minutes) | hops | one-time Ed25519 key | signature | circle tag | body length | body + random padding
 * The signature is made with a key invented for this one message, so it proves integrity but names nobody.
 * Who the sender really is lives only inside the end-to-end encrypted body.
 */
class MeshEnvelope(val id: ByteArray, val expiryMin: Long, val hops: Int, val eph: ByteArray, val sig: ByteArray, val tag: ByteArray, val body: ByteArray) {
    companion object {
        const val VERSION = 1
        const val HEADER = 1 + 16 + 4 + 1 + 32 + 64 + 16 + 2
        const val MAX_BODY = MESH_ENVELOPE - HEADER
        private val rnd = SecureRandom()

        private fun signedPart(id: ByteArray, expiryMin: Long, body: ByteArray): ByteArray =
            ByteBuffer.allocate(1 + 16 + 4 + 2 + body.size).put(VERSION.toByte()).put(id).putInt(expiryMin.toInt()).putShort(body.size.toShort()).put(body).array()

        fun build(circle: MeshCircle, ciphertext: ByteArray, expiryMin: Long): ByteArray {
            require(ciphertext.size in 1..MAX_BODY) { "body does not fit" }
            val id = ByteArray(16).also { rnd.nextBytes(it) }
            val signer = SeedSigner(SeedSigner.newSeed())                   // thrown away after this one message
            val part = signedPart(id, expiryMin, ciphertext)
            val sig = signer.sign(part)
            val tag = circle.tag(part + signer.publicKey)
            val out = ByteArray(MESH_ENVELOPE).also { rnd.nextBytes(it) }   // padding is random, not zeros
            val b = ByteBuffer.wrap(out)
            b.put(VERSION.toByte()).put(id).putInt(expiryMin.toInt()).put(0.toByte()).put(signer.publicKey).put(sig).put(tag).putShort(ciphertext.size.toShort()).put(ciphertext)
            return out
        }

        /** Structure only; call [verify] before trusting anything. Null if malformed. */
        fun parse(raw: ByteArray): MeshEnvelope? {
            if (raw.size != MESH_ENVELOPE || raw[0].toInt() != VERSION) return null
            val b = ByteBuffer.wrap(raw); b.get()
            val id = ByteArray(16).also { b.get(it) }; val exp = b.int.toLong() and 0xffffffffL; val hops = b.get().toInt() and 0xff
            val eph = ByteArray(32).also { b.get(it) }; val sig = ByteArray(64).also { b.get(it) }; val tag = ByteArray(16).also { b.get(it) }
            val len = b.short.toInt() and 0xffff
            if (len < 1 || len > MAX_BODY) return null
            return MeshEnvelope(id, exp, hops, eph, sig, tag, ByteArray(len).also { b.get(it) })
        }

        fun verify(e: MeshEnvelope, circle: MeshCircle): Boolean {
            val part = signedPart(e.id, e.expiryMin, e.body)
            return MessageDigest.isEqual(circle.tag(part + e.eph), e.tag) && Ed25519Verify.verify(e.eph, part, e.sig)
        }

        /** Relays change only the hop counter; it is not covered by the signature. */
        fun withHops(raw: ByteArray, hops: Int): ByteArray = raw.copyOf().also { it[21] = hops.toByte() }
    }
}
