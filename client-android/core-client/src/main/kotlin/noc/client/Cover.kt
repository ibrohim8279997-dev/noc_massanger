package noc.client

import java.security.SecureRandom

interface Exchanger { fun exchange(slot: ByteArray): ByteArray }

enum class CoverMode { NORMAL, PARANOID }

/**
 * Constant-size, constant-rate channel to the server.
 *
 * Every period the client sends ONE slot of exactly SLOT_UP bytes and gets back ONE slot of exactly SLOT_DOWN bytes.
 * A real outgoing message takes the place of the dummy upload; a real incoming packet takes the place of the dummy
 * download. Nothing about size or timing tells an observer which slots carry real data.
 *   NORMAL:   full rate while the user is active and for [activeWindowMs] afterwards, then a slow heartbeat (same slot format)
 *   PARANOID: one constant rate all the time (slower than the active rate: the data cost of constant 2 s slots is ~1.4 GB/day)
 */
class CoverChannel(
    private val ex: Exchanger,
    private val recv: () -> List<Pair<ByteArray, ByteArray>>,       // (mailbox id, token) to download from, round-robin
    private val mode: () -> CoverMode,
    private val onPacket: (ByteArray) -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
    val activePeriodMs: Long = 2_000, val idlePeriodMs: Long = 30_000, val activeWindowMs: Long = 180_000,
    val paranoidPeriodMs: Long = 5_000,
    private val onUploadFailed: (ByteArray) -> Unit = {},
    private val maxTries: Int = 5,
) {
    companion object {
        const val ENVELOPE = 16384
        const val SLOT_UP = 1 + 16 + 32 + 16 + 16 + ENVELOPE
        const val SLOT_DOWN = 1 + 16 + ENVELOPE
        const val F_UPLOAD = 1; const val F_ACK = 2
        const val D_HAS_PACKET = 1; const val D_UNAUTH = 2; const val D_REJECTED = 4
    }

    private class Up(val dest: ByteArray, val env: ByteArray, var tries: Int = 0)
    private val rnd = SecureRandom()
    private val queue = ArrayDeque<Up>()
    private val pendingAck = HashMap<String, ByteArray>()
    private val lastDelivered = HashMap<String, String>()
    private var activeUntil = 0L
    private var slotNo = 0
    @Volatile var slotsSent = 0; private set

    @Synchronized fun enqueue(dest: ByteArray, envelope: ByteArray) { require(envelope.size == ENVELOPE); queue.addLast(Up(dest, envelope)); touch() }
    @Synchronized fun touch() { activeUntil = clock() + activeWindowMs }
    @Synchronized fun queued() = queue.size

    @Synchronized fun periodMs(): Long = when {
        mode() == CoverMode.PARANOID -> paranoidPeriodMs          // constant, whatever the user does
        clock() < activeUntil -> activePeriodMs
        else -> idlePeriodMs
    }

    private fun rb(n: Int) = ByteArray(n).also { rnd.nextBytes(it) }
    private fun key(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    /** Builds and sends one slot. Returns true if the exchange itself succeeded. */
    fun exchangeOnce(): Boolean {
        val up: Up?; val box: Pair<ByteArray, ByteArray>?; val ackId: ByteArray?
        synchronized(this) {
            val list = recv()
            box = if (list.isEmpty()) null else list[slotNo++ % list.size]
            up = queue.removeFirstOrNull()
            ackId = box?.let { pendingAck.remove(key(it.first)) }
        }
        var flags = 0
        if (up != null) flags = flags or F_UPLOAD
        if (ackId != null) flags = flags or F_ACK
        val slot = byteArrayOf(flags.toByte()) + (box?.first ?: rb(16)) + (box?.second ?: rb(32)) + (ackId ?: rb(16)) + (up?.dest ?: rb(16)) + (up?.env ?: rb(ENVELOPE))
        check(slot.size == SLOT_UP)
        val resp = try { ex.exchange(slot) } catch (e: Exception) {
            synchronized(this) { up?.let { queue.addFirst(it) }; if (ackId != null && box != null) pendingAck[key(box.first)] = ackId }
            return false
        }
        slotsSent++
        if (resp.size != SLOT_DOWN) return false
        val df = resp[0].toInt()
        if (up != null && df and D_REJECTED != 0) {
            synchronized(this) { up.tries++; if (up.tries < maxTries) queue.addFirst(up) else onUploadFailed(up.dest) }
        }
        if (box != null && df and D_HAS_PACKET != 0 && df and D_UNAUTH == 0) {
            val pid = resp.copyOfRange(1, 17); val mk = key(box.first)
            if (lastDelivered[mk] != key(pid)) {
                lastDelivered[mk] = key(pid)
                touch()
                try { onPacket(resp.copyOfRange(17, SLOT_DOWN)) } catch (e: Exception) { }   // undecryptable packets are dropped, never retried forever
            }
            synchronized(this) { pendingAck[mk] = pid }
        }
        return true
    }

    /** Runs until [stop] says so. Keeps the rate constant by subtracting the time a slot took. */
    fun run(stop: () -> Boolean, sleep: (Long) -> Unit = { Thread.sleep(it) }) {
        while (!stop()) {
            val t0 = clock()
            exchangeOnce()
            var left = periodMs() - (clock() - t0)
            while (left > 0 && !stop()) { val d = minOf(left, 200L); sleep(d); left -= d }   // sliced so that stopping is quick
        }
    }
}
