package noc.mesh

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One link to one neighbour, whatever the radio (Bluetooth, Wi-Fi Direct, Nearby Connections).
 *  1. mutual proof of circle membership (challenge-response with the circle key), so a stranger who merely connects gets nothing;
 *  2. then the normal MeshMsg exchange (hello / want / envelope / ack).
 * [fragment]: slow radios (BLE) cut an envelope into small checksummed fragments; fast links send it whole.
 * [initiator]: the side that opened the connection. It makes the roles different, so a proof cannot be reflected back.
 */
class MeshSession(
    private val node: MeshNode, private val circle: MeshCircle, private val initiator: Boolean, private val fragment: Boolean,
    private val send: (ByteArray) -> Unit, private val onClosed: () -> Unit = {},
) {
    private val rnd = SecureRandom()
    val label = "peer-" + rnd.nextLong().toString(16)            // throw-away; forgotten at close()
    private val myNonce = ByteArray(16).also { rnd.nextBytes(it) }
    private var peerNonce: ByteArray? = null
    @Volatile var authenticated = false; private set
    @Volatile var closed = false; private set
    private var reasm = Fragments.Reassembler()

    companion object {
        private const val T_NONCE = 0xA0.toByte(); private const val T_PROOF = 0xA1.toByte(); private const val T_FRAG = 0xF0.toByte()
        const val MAX_FRAME = MESH_ENVELOPE + 64
    }

    /** Call when the link is up. */
    @Synchronized fun start() { send(byteArrayOf(T_NONCE) + myNonce) }

    private fun proof(prover: Boolean /* is the prover the initiator? */, nonceInit: ByteArray, nonceResp: ByteArray): ByteArray =
        circle.tag(byteArrayOf(if (prover) 1 else 0) + "NOC-MESH-AUTH".toByteArray() + nonceInit + nonceResp)

    @Synchronized fun onFrame(f: ByteArray) {
        if (closed || f.isEmpty() || f.size > MAX_FRAME) return
        when (f[0]) {
            T_NONCE -> if (peerNonce == null && f.size == 17) {
                peerNonce = f.copyOfRange(1, 17)
                val (ni, nr) = if (initiator) myNonce to peerNonce!! else peerNonce!! to myNonce
                send(byteArrayOf(T_PROOF) + proof(initiator, ni, nr))
            }
            T_PROOF -> {
                val pn = peerNonce ?: return close()                                    // proof before nonce: not a member
                val (ni, nr) = if (initiator) myNonce to pn else pn to myNonce
                if (f.size != 17 || !MessageDigest.isEqual(f.copyOfRange(1, 17), proof(!initiator, ni, nr))) return close()   // not in the circle: hang up silently
                authenticated = true
                offer()
            }
            else -> if (authenticated) data(f) else close()                             // nothing but the handshake before authentication
        }
    }

    private fun data(f: ByteArray) {
        if (f[0] == T_FRAG) {
            if (reasm.add(f.copyOfRange(1, f.size))) reasm.result()?.let { env -> reasm = Fragments.Reassembler(); reply(node.handle(label, MeshMsg.Env(env))) }
        } else MeshMsg.decode(f)?.let { reply(node.handle(label, it)) }
    }

    /** Bluetooth frames must stay small (~240 bytes): long hash lists are split into several hello/want messages (each is handled on its own). */
    private val maxHashes = if (fragment) 20 else 400

    private fun reply(msgs: List<MeshMsg>) = msgs.forEach { m ->
        when {
            m is MeshMsg.Env && fragment -> Fragments.split(m.envelope).forEach { send(byteArrayOf(T_FRAG) + it) }
            m is MeshMsg.Hello && m.hashes.size > maxHashes -> m.hashes.chunked(maxHashes).forEach { send(MeshMsg.Hello(it).encode()) }
            m is MeshMsg.Want && m.hashes.size > maxHashes -> m.hashes.chunked(maxHashes).forEach { send(MeshMsg.Want(it).encode()) }
            else -> send(m.encode())
        }
    }

    /** Offer everything we carry. Safe to call again while the link stays up (new envelopes appear over time). */
    @Synchronized fun offer() { if (authenticated && !closed) { node.end(label); reply(listOf(node.begin(label))) } }

    @Synchronized fun close() {
        if (closed) return
        closed = true; node.end(label); onClosed()
    }
}

/** Length-prefixed frames over a byte stream (TCP sockets of Wi-Fi Direct). Oversized or short frames are refused. */
object FrameStream {
    fun write(out: OutputStream, frame: ByteArray) { DataOutputStream(out).apply { writeInt(frame.size); write(frame); flush() } }
    fun read(input: InputStream): ByteArray {
        val d = DataInputStream(input)
        val n = d.readInt()
        if (n < 0 || n > MeshSession.MAX_FRAME) throw java.io.IOException("bad frame length")
        return ByteArray(n).also { d.readFully(it) }
    }
}
