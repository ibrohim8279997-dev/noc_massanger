package noc.crypto

import java.nio.ByteBuffer

const val ENVELOPE_SIZE = 16384

enum class Kind(val code: Int) {
    TEXT(1), FILE_MANIFEST(2), FILE_CHUNK(3);
    companion object { fun of(c: Int) = entries.firstOrNull { it.code == c } ?: throw MalformedException("kind") }
}

class MalformedException(msg: String) : Exception(msg)

/** Everything the server must not see lives in here: sender, time, type, disappearing-timer. */
data class Inner(
    val kind: Kind,
    val senderDeviceKey: ByteArray,   // 32-byte Ed25519 key of the sender
    val sentAtMs: Long,
    val expireAfterS: Int,            // 0 = keep; otherwise delete this many seconds after reading
    val payload: ByteArray,
) {
    fun encode(): ByteArray {
        require(senderDeviceKey.size == 32)
        val b = ByteBuffer.allocate(1 + 32 + 8 + 4 + payload.size)
        b.put(kind.code.toByte()).put(senderDeviceKey).putLong(sentAtMs).putInt(expireAfterS).put(payload)
        return b.array()
    }

    companion object {
        fun decode(raw: ByteArray): Inner {
            if (raw.size < 45) throw MalformedException("short")
            val b = ByteBuffer.wrap(raw)
            val kind = Kind.of(b.get().toInt())
            val key = ByteArray(32).also { b.get(it) }
            val ts = b.getLong()
            val exp = b.getInt()
            if (exp < 0) throw MalformedException("ttl")
            return Inner(kind, key, ts, exp, ByteArray(b.remaining()).also { b.get(it) })
        }
    }
}
