package noc.mesh

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/** Messages two neighbours exchange during one encounter. [peer] handles are throw-away labels, never stored. */
sealed class MeshMsg {
    class Hello(val hashes: List<Long>) : MeshMsg()
    class Want(val hashes: List<Long>) : MeshMsg()
    class Env(val envelope: ByteArray) : MeshMsg()
    class Ack(val hash: Long) : MeshMsg()

    fun encode(): ByteArray = when (this) {
        is Hello -> ByteBuffer.allocate(3 + 8 * hashes.size).put(1).putShort(hashes.size.toShort()).also { b -> hashes.forEach { b.putLong(it) } }.array()
        is Want -> ByteBuffer.allocate(3 + 8 * hashes.size).put(2).putShort(hashes.size.toShort()).also { b -> hashes.forEach { b.putLong(it) } }.array()
        is Env -> byteArrayOf(3) + envelope
        is Ack -> ByteBuffer.allocate(9).put(4).putLong(hash).array()
    }

    companion object {
        fun decode(raw: ByteArray): MeshMsg? = try {
            val b = ByteBuffer.wrap(raw)
            when (b.get().toInt()) {
                1 -> Hello(List(b.short.toInt() and 0xffff) { b.long }.also { if (b.hasRemaining()) return null })
                2 -> Want(List(b.short.toInt() and 0xffff) { b.long }.also { if (b.hasRemaining()) return null })
                3 -> Env(ByteArray(b.remaining()).also { b.get(it) })
                4 -> Ack(b.long).also { if (b.hasRemaining()) return null }
                else -> null
            }
        } catch (e: Exception) { null }
    }
}

class Limits(
    val maxEntries: Int = 64,                 // relay buffer: at most this many envelopes...
    val maxBytes: Long = 64L * MESH_ENVELOPE, // ...and this many bytes
    val fanout: Int = 3,                      // hand a message to this many different neighbours, then forget it
    val maxHops: Int = 6,
    val ttlMinutes: Long = 12 * 60,
    val perEncounterIn: Int = 32,             // spam guard: envelopes accepted from one neighbour per encounter
    val strikesToDrop: Int = 3,
)

/**
 * A phone in the mesh: carries sealed envelopes it cannot read, hands them to neighbours, then forgets them.
 *  - [onDeliver] gets the Signal ciphertext of every accepted envelope; it returns true if the message was for us (then we keep nothing).
 *  - An envelope is deleted when [Limits.fanout] neighbours have acknowledged it, or when it expires. Not earlier.
 *  - After deletion nothing remains but a 64-bit hash of the one-time message id in two RAM-only generations (to avoid loops).
 */
class MeshNode(
    private val circle: MeshCircle, private val store: EnvelopeStore, private val clock: () -> Long,
    private val onDeliver: (ByteArray) -> Boolean, val limits: Limits = Limits(),
) {
    private class Entry(val id: ByteArray, val expiryMin: Long, val hops: Int) { var handoffs = 0 }
    private class Encounter { var sent = 0; var received = 0; var strikes = 0; var dead = false }

    private val entries = LinkedHashMap<Long, Entry>()          // hash -> entry
    private var tombNew = HashSet<Long>(); private var tombOld = HashSet<Long>()
    private var tombRotatedAt = clock()
    private val encounters = HashMap<String, Encounter>()
    private val rnd = SecureRandom()

    private fun h(id: ByteArray): Long = ByteBuffer.wrap(MessageDigest.getInstance("SHA-256").digest("NOC-MESH-H".toByteArray() + id)).long
    private fun nowMin() = clock() / 60_000

    fun held() = entries.size
    fun stored() = store.count()
    fun tombstones() = tombNew.size + tombOld.size

    // ------------------------------------------------------------ origin
    /** Wraps a Signal ciphertext into an envelope and starts carrying it. */
    @Synchronized fun inject(ciphertext: ByteArray): Boolean {
        if (ciphertext.size > MeshEnvelope.MAX_BODY) return false
        val raw = MeshEnvelope.build(circle, ciphertext, nowMin() + limits.ttlMinutes)
        val e = MeshEnvelope.parse(raw)!!
        keep(e, raw)
        return true
    }

    // ------------------------------------------------------------ encounters
    @Synchronized fun begin(peer: String): MeshMsg {
        purge()
        encounters[peer] = Encounter()
        return MeshMsg.Hello(entries.filter { (_, e) -> e.handoffs < limits.fanout && e.hops < limits.maxHops }.keys.toList())
    }

    @Synchronized fun end(peer: String) { encounters.remove(peer) }

    @Synchronized fun handle(peer: String, msg: MeshMsg): List<MeshMsg> {
        val enc = encounters[peer] ?: return emptyList()
        if (enc.dead) return emptyList()
        return when (msg) {
            is MeshMsg.Hello -> {
                val (have, need) = msg.hashes.partition { known(it) }
                // what we already hold (or have already handled) is acknowledged right away, so the offering side may let go of it
                listOf<MeshMsg>(MeshMsg.Want(need.take(limits.perEncounterIn))) + have.take(limits.perEncounterIn).map { MeshMsg.Ack(it) }
            }
            is MeshMsg.Want -> msg.hashes.mapNotNull { hh ->
                val e = entries[hh] ?: return@mapNotNull null
                if (e.handoffs >= limits.fanout || e.hops >= limits.maxHops || nowMin() >= e.expiryMin) return@mapNotNull null
                val raw = store.get(e.id) ?: return@mapNotNull null
                enc.sent++
                MeshMsg.Env(MeshEnvelope.withHops(raw, e.hops + 1))
            }
            is MeshMsg.Env -> receive(enc, msg.envelope)
            is MeshMsg.Ack -> { ack(msg.hash); emptyList() }
        }
    }

    private fun known(hash: Long) = entries.containsKey(hash) || hash in tombNew || hash in tombOld

    private fun receive(enc: Encounter, raw: ByteArray): List<MeshMsg> {
        fun strike(): List<MeshMsg> { if (++enc.strikes >= limits.strikesToDrop) enc.dead = true; return emptyList() }
        if (++enc.received > limits.perEncounterIn) return strike()
        val e = MeshEnvelope.parse(raw) ?: return strike()
        if (!MeshEnvelope.verify(e, circle)) return strike()                 // forged, tampered or from outside the circle
        if (nowMin() >= e.expiryMin || e.expiryMin > nowMin() + limits.ttlMinutes + 5) return strike()   // expired, or a ttl longer than we allow
        if (e.hops > limits.maxHops) return strike()
        val hh = h(e.id)
        if (known(hh)) return listOf(MeshMsg.Ack(hh))                         // already handled: acknowledge so the sender can let go
        val mine = try { onDeliver(e.body) } catch (ex: Exception) { false }
        if (mine) tomb(hh) else keep(e, raw)                                  // for us: consume, keep nothing. Otherwise carry it on.
        return listOf(MeshMsg.Ack(hh))
    }

    private fun ack(hash: Long) {
        val e = entries[hash] ?: return
        if (++e.handoffs >= limits.fanout) drop(hash)
    }

    // ------------------------------------------------------------ buffer
    private fun keep(e: MeshEnvelope, raw: ByteArray) {
        // bounded: make room by dropping what would expire first
        while (entries.size >= limits.maxEntries || (entries.size + 1) * MESH_ENVELOPE.toLong() > limits.maxBytes) {
            val victim = entries.minByOrNull { it.value.expiryMin }?.key ?: break
            drop(victim)
        }
        entries[h(e.id)] = Entry(e.id, e.expiryMin, e.hops)
        store.put(e.id, raw)
    }

    private fun drop(hash: Long) {
        val e = entries.remove(hash) ?: return
        store.delete(e.id)                                                   // envelope gone (overwritten on disk)
        tomb(hash)
    }

    private fun tomb(hash: Long) { tombNew.add(hash) }

    /** Time-based cleanup. Tombstones rotate in two generations, so no per-item time is ever kept. */
    @Synchronized fun purge() {
        val now = nowMin()
        entries.filter { it.value.expiryMin <= now }.keys.toList().forEach { drop(it) }
        if (clock() - tombRotatedAt >= limits.ttlMinutes * 60_000) { tombOld = tombNew; tombNew = HashSet(); tombRotatedAt = clock() }
    }

    /** Everything this node remembers, as text. Used by tests to prove that no trace of a neighbour or recipient is kept. */
    @Synchronized fun snapshot(): String = buildString {
        append("entries=").append(entries.map { "${it.key}:${it.value.expiryMin}:${it.value.hops}:${it.value.handoffs}" })
        append(" tombstones=").append(tombNew.size + tombOld.size).append(" encounters=").append(encounters.keys)
    }
}
