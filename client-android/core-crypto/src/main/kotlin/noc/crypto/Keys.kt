package noc.crypto

import org.signal.libsignal.protocol.*
import org.signal.libsignal.protocol.ecc.*
import org.signal.libsignal.protocol.kem.*
import org.signal.libsignal.protocol.state.*
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore
import java.io.*
import java.security.SecureRandom

/** Long-term public part (served by the server as an opaque blob). */
class LongTermBundle(
    val registrationId: Int, val deviceId: Int, val identity: IdentityKey,
    val signedId: Int, val signedKey: ECPublicKey, val signedSig: ByteArray,
    val kyberId: Int, val kyberKey: KEMPublicKey, val kyberSig: ByteArray,
) {
    fun serialize(): ByteArray = ByteArrayOutputStream().also { bo ->
        DataOutputStream(bo).run {
            writeInt(registrationId); writeInt(deviceId)
            blob(identity.serialize()); writeInt(signedId); blob(signedKey.serialize()); blob(signedSig)
            writeInt(kyberId); blob(kyberKey.serialize()); blob(kyberSig)
        }
    }.toByteArray()

    fun toBundle(otp: OneTime?): PreKeyBundle = PreKeyBundle(
        registrationId, deviceId, otp?.id ?: PreKeyBundle.NULL_PRE_KEY_ID, otp?.key,
        signedId, signedKey, signedSig, identity, kyberId, kyberKey, kyberSig)

    companion object {
        fun parse(raw: ByteArray): LongTermBundle = try {
            DataInputStream(ByteArrayInputStream(raw)).run {
                val reg = readInt(); val dev = readInt()
                val ik = IdentityKey(blob()); val sid = readInt(); val sk = ECPublicKey(blob()); val ss = blob()
                val kid = readInt(); val kk = KEMPublicKey(blob()); val ks = blob()
                LongTermBundle(reg, dev, ik, sid, sk, ss, kid, kk, ks)
            }
        } catch (e: Exception) { throw MalformedException("bundle") }
    }
}

class OneTime(val id: Int, val key: ECPublicKey) {
    fun serialize(): ByteArray = ByteArrayOutputStream().also { DataOutputStream(it).run { writeInt(id); blob(key.serialize()) } }.toByteArray()
    companion object {
        fun parse(raw: ByteArray): OneTime = try {
            DataInputStream(ByteArrayInputStream(raw)).run { OneTime(readInt(), ECPublicKey(blob())) }
        } catch (e: Exception) { throw MalformedException("one-time key") }
    }
}

internal fun DataOutputStream.blob(b: ByteArray) { writeInt(b.size); write(b) }
internal fun DataInputStream.blob(): ByteArray {
    val n = readInt(); if (n < 0 || n > 16384) throw IOException("bad length"); return ByteArray(n).also { readFully(it) }
}

/**
 * Signal store that only trusts identities pinned by hand (QR meeting).
 * A different key for a known contact is refused until the user explicitly accepts it.
 */
class StrictStore(identity: IdentityKeyPair, regId: Int) : InMemorySignalProtocolStore(identity, regId), PinnedStore {
    private val pinned = HashMap<String, IdentityKey>()

    override fun pin(addr: SignalProtocolAddress, key: IdentityKey) { pinned[addr.toString()] = key }
    override fun isPinned(addr: SignalProtocolAddress) = pinned.containsKey(addr.toString())

    /** Called only after the user confirmed the warning about a changed key. */
    override fun acceptKeyChange(addr: SignalProtocolAddress, newKey: IdentityKey) {
        pinned[addr.toString()] = newKey
        deleteSession(addr)  // old ratchet state belongs to the old key
        super.saveIdentity(addr, newKey)
    }

    override fun isTrustedIdentity(address: SignalProtocolAddress, key: IdentityKey, dir: IdentityKeyStore.Direction): Boolean =
        pinned[address.toString()]?.let { it == key } ?: false
}

/** A local user: identity, signed prekey, Kyber prekey, a batch of one-time prekeys. */
class LocalIdentity private constructor(val store: PinnedStore, val bundle: LongTermBundle, private val otpIds: MutableList<Int>) {
    val identityKey: IdentityKey get() = store.identityKeyPair.publicKey

    /** Tops up one-time prekeys to [target] (ids are random, never reused while still stored). */
    fun refill(target: Int = 20) {
        otpIds.removeAll { !store.containsPreKey(it) }
        while (otpIds.size < target) {
            val id = rnd.nextInt(0xFFFFFF - 100_000) + 100_000
            if (store.containsPreKey(id)) continue
            store.storePreKey(id, PreKeyRecord(id, ECKeyPair.generate())); otpIds.add(id)
        }
    }

    fun oneTimeKeys(): List<OneTime> = otpIds.filter { store.containsPreKey(it) }.map { OneTime(it, store.loadPreKey(it).keyPair.publicKey) }

    companion object {
        private val rnd = SecureRandom()
        fun create(oneTimeCount: Int = 20): LocalIdentity {
            val idp = IdentityKeyPair.generate()
            return build(StrictStore(idp, rnd.nextInt(16379) + 1), idp, oneTimeCount)
        }

        /** Loads the identity saved in [kv], or creates and saves a new one on first start. */
        fun loadOrCreate(kv: Kv, oneTimeCount: Int = 20): LocalIdentity {
            val saved = kv.get("self", "identity")
            if (saved != null) {
                val idp = IdentityKeyPair(saved)
                val store = PersistentSignalStore(kv, idp, java.nio.ByteBuffer.wrap(kv.get("self", "regid")!!).int)
                val lt = LongTermBundle.parse(kv.get("self", "bundle")!!)
                return LocalIdentity(store, lt, kv.keys("prekey").map { it.toInt() }.sorted().toMutableList())
            }
            val idp = IdentityKeyPair.generate()
            val reg = rnd.nextInt(16379) + 1
            kv.put("self", "identity", idp.serialize()); kv.put("self", "regid", java.nio.ByteBuffer.allocate(4).putInt(reg).array())
            val me = build(PersistentSignalStore(kv, idp, reg), idp, oneTimeCount)
            kv.put("self", "bundle", me.bundle.serialize())
            return me
        }

        private fun build(store: PinnedStore, idp: IdentityKeyPair, oneTimeCount: Int): LocalIdentity {
            val now = System.currentTimeMillis()
            val spk = ECKeyPair.generate()
            val sig = idp.privateKey.calculateSignature(spk.publicKey.serialize())
            store.storeSignedPreKey(1, SignedPreKeyRecord(1, now, spk, sig))
            val kem = KEMKeyPair.generate(KEMKeyType.KYBER_1024)
            val ksig = idp.privateKey.calculateSignature(kem.publicKey.serialize())
            store.storeKyberPreKey(1, KyberPreKeyRecord(1, now, kem, ksig))
            val ids = (1..oneTimeCount).map { id -> store.storePreKey(id, PreKeyRecord(id, ECKeyPair.generate())); id }
            val lt = LongTermBundle(store.localRegistrationId, 1, idp.publicKey, 1, spk.publicKey, sig, 1, kem.publicKey, ksig)
            return LocalIdentity(store, lt, ids.toMutableList())
        }
    }
}
