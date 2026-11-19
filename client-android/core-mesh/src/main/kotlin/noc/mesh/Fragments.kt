package noc.mesh

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.zip.CRC32

/**
 * Radio links carry small packets (BLE: a few hundred bytes). An envelope is sent as fragments:
 *   session(4) | index(2) | total(2) | length(1) | payload | crc32(4)
 * The data being fragmented is  envelope || SHA-256(envelope), so the whole envelope has a checksum too.
 */
object Fragments {
    const val PAYLOAD = 180
    private val rnd = SecureRandom()

    fun split(envelope: ByteArray, session: Int = rnd.nextInt()): List<ByteArray> {
        val data = envelope + MessageDigest.getInstance("SHA-256").digest(envelope)
        val total = (data.size + PAYLOAD - 1) / PAYLOAD
        return (0 until total).map { i ->
            val part = data.copyOfRange(i * PAYLOAD, minOf(data.size, (i + 1) * PAYLOAD))
            val b = ByteBuffer.allocate(9 + part.size + 4).putInt(session).putShort(i.toShort()).putShort(total.toShort()).put(part.size.toByte()).put(part)
            val crc = CRC32().apply { update(b.array(), 0, 9 + part.size) }.value
            b.putInt(crc.toInt()).array()
        }
    }

    class Reassembler {
        private var session: Int? = null
        private var total = 0
        private val parts = HashMap<Int, ByteArray>()

        /** True if the fragment was good and (new or a harmless repeat). Bad checksums, other sessions and nonsense are refused. */
        fun add(f: ByteArray): Boolean {
            if (f.size < 13) return false
            val b = ByteBuffer.wrap(f)
            val sid = b.int; val idx = b.short.toInt() and 0xffff; val tot = b.short.toInt() and 0xffff; val len = b.get().toInt() and 0xff
            if (len > PAYLOAD || f.size != 9 + len + 4 || tot < 2 || tot > 64 || idx >= tot) return false
            val crc = CRC32().apply { update(f, 0, 9 + len) }.value
            if (crc.toInt() != ByteBuffer.wrap(f, 9 + len, 4).int) return false
            if (session == null) { session = sid; total = tot } else if (session != sid || total != tot) return false
            parts.putIfAbsent(idx, f.copyOfRange(9, 9 + len))
            return true
        }

        fun missing(): List<Int> = (0 until total).filter { it !in parts }
        fun complete() = session != null && missing().isEmpty()

        /** The envelope, only if every fragment arrived and the SHA-256 matches. */
        fun result(): ByteArray? {
            if (!complete()) return null
            val data = ByteBuffer.allocate(parts.values.sumOf { it.size }).also { o -> (0 until total).forEach { o.put(parts[it]!!) } }.array()
            if (data.size != MESH_ENVELOPE + 32) return null
            val env = data.copyOfRange(0, MESH_ENVELOPE)
            return if (MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(env), data.copyOfRange(MESH_ENVELOPE, data.size))) env else null
        }
    }
}
