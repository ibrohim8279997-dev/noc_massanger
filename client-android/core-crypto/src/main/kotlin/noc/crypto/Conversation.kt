package noc.crypto

import org.signal.libsignal.protocol.*
import org.signal.libsignal.protocol.message.*

/** One peer. Encrypts Inner messages into fixed-size envelopes and back. */
class Conversation(private val me: LocalIdentity, val peer: SignalProtocolAddress) {
    private val store: PinnedStore = me.store

    /** Start from the peer's published keys; peer identity must already be pinned from the QR meeting. */
    fun startFrom(lt: LongTermBundle, otp: OneTime?) {
        if (!store.isPinned(peer)) throw UntrustedIdentityException(peer.name)
        SessionBuilder(store, peer).process(lt.toBundle(otp))
    }

    fun seal(msg: Inner): ByteArray {
        val ct = SessionCipher(store, peer).encrypt(msg.encode())
        return Envelope.pack(ct.serialize())
    }

    fun open(envelope: ByteArray): Inner {
        val raw = Envelope.unpack(envelope)
        val cipher = SessionCipher(store, peer)
        val plain = try {
            cipher.decrypt(PreKeySignalMessage(raw))
        } catch (e: InvalidMessageException) {
            cipher.decrypt(SignalMessage(raw))
        } catch (e: InvalidVersionException) {
            cipher.decrypt(SignalMessage(raw))
        }
        return Inner.decode(plain)
    }
}
