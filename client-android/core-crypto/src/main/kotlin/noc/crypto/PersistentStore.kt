package noc.crypto

import org.signal.libsignal.protocol.*
import org.signal.libsignal.protocol.ecc.ECPublicKey
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord
import org.signal.libsignal.protocol.state.*
import java.util.UUID

/** Minimal byte key-value interface. The Android app backs it with SQLCipher; tests use memory. */
interface Kv {
    fun get(ns: String, key: String): ByteArray?
    fun put(ns: String, key: String, value: ByteArray)
    fun delete(ns: String, key: String)
    fun keys(ns: String): List<String>
}

class MemoryKv : Kv {
    private val m = HashMap<String, ByteArray>()
    override fun get(ns: String, key: String) = m["$ns/$key"]
    override fun put(ns: String, key: String, value: ByteArray) { m["$ns/$key"] = value }
    override fun delete(ns: String, key: String) { m.remove("$ns/$key") }
    override fun keys(ns: String) = m.keys.filter { it.startsWith("$ns/") }.map { it.removePrefix("$ns/") }
}

/** Trust only identities pinned by hand; a different key is refused until the user accepts it. */
interface PinnedStore : org.signal.libsignal.protocol.state.SignalProtocolStore {
    fun pin(addr: SignalProtocolAddress, key: IdentityKey)
    fun isPinned(addr: SignalProtocolAddress): Boolean
    fun acceptKeyChange(addr: SignalProtocolAddress, newKey: IdentityKey)
}

class PersistentSignalStore(private val kv: Kv, private val identity: IdentityKeyPair, private val regId: Int) : PinnedStore {
    private fun k(a: SignalProtocolAddress) = "${a.name}:${a.deviceId}"

    // identity / trust
    override fun getIdentityKeyPair() = identity
    override fun getLocalRegistrationId() = regId
    override fun saveIdentity(a: SignalProtocolAddress, key: IdentityKey): IdentityKeyStore.IdentityChange {
        val old = kv.get("identity", k(a)); kv.put("identity", k(a), key.serialize())
        return if (old == null || old.contentEquals(key.serialize())) IdentityKeyStore.IdentityChange.NEW_OR_UNCHANGED
        else IdentityKeyStore.IdentityChange.REPLACED_EXISTING
    }
    override fun isTrustedIdentity(a: SignalProtocolAddress, key: IdentityKey, d: IdentityKeyStore.Direction): Boolean =
        kv.get("pinned", k(a))?.let { IdentityKey(it) == key } ?: false
    override fun getIdentity(a: SignalProtocolAddress): IdentityKey? = kv.get("identity", k(a))?.let { IdentityKey(it) }
    override fun pin(addr: SignalProtocolAddress, key: IdentityKey) { kv.put("pinned", k(addr), key.serialize()) }
    override fun isPinned(addr: SignalProtocolAddress) = kv.get("pinned", k(addr)) != null
    override fun acceptKeyChange(addr: SignalProtocolAddress, newKey: IdentityKey) {
        kv.put("pinned", k(addr), newKey.serialize()); kv.put("identity", k(addr), newKey.serialize()); deleteSession(addr)
    }

    // one-time prekeys
    override fun loadPreKey(id: Int) = kv.get("prekey", "$id")?.let { PreKeyRecord(it) } ?: throw InvalidKeyIdException("no prekey $id")
    override fun storePreKey(id: Int, r: PreKeyRecord) = kv.put("prekey", "$id", r.serialize())
    override fun containsPreKey(id: Int) = kv.get("prekey", "$id") != null
    override fun removePreKey(id: Int) = kv.delete("prekey", "$id")

    // signed prekeys
    override fun loadSignedPreKey(id: Int) = kv.get("signed", "$id")?.let { SignedPreKeyRecord(it) } ?: throw InvalidKeyIdException("no signed $id")
    override fun loadSignedPreKeys() = kv.keys("signed").map { SignedPreKeyRecord(kv.get("signed", it)!!) }
    override fun storeSignedPreKey(id: Int, r: SignedPreKeyRecord) = kv.put("signed", "$id", r.serialize())
    override fun containsSignedPreKey(id: Int) = kv.get("signed", "$id") != null
    override fun removeSignedPreKey(id: Int) = kv.delete("signed", "$id")

    // kyber prekeys (ML-KEM-1024); ours are "last resort": reusable, but a base key may be used only once
    override fun loadKyberPreKey(id: Int) = kv.get("kyber", "$id")?.let { KyberPreKeyRecord(it) } ?: throw InvalidKeyIdException("no kyber $id")
    override fun loadKyberPreKeys() = kv.keys("kyber").map { KyberPreKeyRecord(kv.get("kyber", it)!!) }
    override fun storeKyberPreKey(id: Int, r: KyberPreKeyRecord) = kv.put("kyber", "$id", r.serialize())
    override fun containsKyberPreKey(id: Int) = kv.get("kyber", "$id") != null
    override fun markKyberPreKeyUsed(id: Int, signedId: Int, baseKey: ECPublicKey) {
        val key = "$id:$signedId:" + baseKey.serialize().joinToString("") { "%02x".format(it) }
        if (kv.get("kyber_used", key) != null) throw ReusedBaseKeyException()
        kv.put("kyber_used", key, byteArrayOf(1))
    }

    // sessions
    override fun loadSession(a: SignalProtocolAddress): SessionRecord = kv.get("session", k(a))?.let { SessionRecord(it) } ?: SessionRecord()
    override fun loadExistingSessions(addrs: MutableList<SignalProtocolAddress>): MutableList<SessionRecord> =
        addrs.map { a -> kv.get("session", k(a))?.let { SessionRecord(it) } ?: throw NoSessionException("no session for ${a.name}") }.toMutableList()
    override fun getSubDeviceSessions(name: String): MutableList<Int> =
        kv.keys("session").filter { it.substringBeforeLast(":") == name }.map { it.substringAfterLast(":").toInt() }.filter { it != 1 }.toMutableList()
    override fun storeSession(a: SignalProtocolAddress, r: SessionRecord) = kv.put("session", k(a), r.serialize())
    override fun containsSession(a: SignalProtocolAddress): Boolean =
        kv.get("session", k(a))?.let { val r = SessionRecord(it); r.hasSenderChain() && r.sessionVersion == 4 } ?: false
    override fun deleteSession(a: SignalProtocolAddress) = kv.delete("session", k(a))
    override fun deleteAllSessions(name: String) { kv.keys("session").filter { it.substringBeforeLast(":") == name }.forEach { kv.delete("session", it) } }

    // sender keys (groups use per-recipient copies, so these stay unused)
    override fun storeSenderKey(a: SignalProtocolAddress, id: UUID, r: SenderKeyRecord) = kv.put("sender", "${k(a)}:$id", r.serialize())
    override fun loadSenderKey(a: SignalProtocolAddress, id: UUID): SenderKeyRecord? = kv.get("sender", "${k(a)}:$id")?.let { SenderKeyRecord(it) }
}
