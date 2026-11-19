package noc.crypto

import java.security.SecureRandom

/**
 * Fixed-size outer packet: [len:2][signal ciphertext][random padding] = ENVELOPE_SIZE bytes.
 * Nothing else is visible outside: no sender, no type, no real length.
 */
object Envelope {
    const val MAX_CIPHERTEXT = ENVELOPE_SIZE - 2
    private val rnd = SecureRandom()

    fun pack(ciphertext: ByteArray): ByteArray {
        if (ciphertext.size > MAX_CIPHERTEXT) throw MalformedException("too large")
        val out = ByteArray(ENVELOPE_SIZE)
        out[0] = (ciphertext.size ushr 8).toByte()
        out[1] = ciphertext.size.toByte()
        System.arraycopy(ciphertext, 0, out, 2, ciphertext.size)
        val pad = ByteArray(ENVELOPE_SIZE - 2 - ciphertext.size).also { rnd.nextBytes(it) }
        System.arraycopy(pad, 0, out, 2 + ciphertext.size, pad.size)
        return out
    }

    fun unpack(envelope: ByteArray): ByteArray {
        if (envelope.size != ENVELOPE_SIZE) throw MalformedException("size")
        val len = ((envelope[0].toInt() and 0xff) shl 8) or (envelope[1].toInt() and 0xff)
        if (len == 0 || len > MAX_CIPHERTEXT) throw MalformedException("length")
        return envelope.copyOfRange(2, 2 + len)
    }
}
