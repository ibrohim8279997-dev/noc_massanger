package noc.app.core

import noc.app.data.Contact
import noc.app.data.Db
import noc.app.net.ServerApi
import noc.crypto.*
import org.signal.libsignal.protocol.SignalProtocolAddress
import java.nio.ByteBuffer
import java.security.SecureRandom

sealed class InviteResult {
    class Added(val contact: Contact, val replyInvite: String?) : InviteResult()
    class KeyChanged(val name: String) : InviteResult()
    object Rejected : InviteResult()
}

private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
private const val MAX_FILE = 20 * 1024 * 1024

/** Glue between storage, crypto and server. All calls block: run them off the main thread. */
class Messenger(private val db: Db, val api: ServerApi) {
    private val rnd = SecureRandom()
    val me: LocalIdentity = LocalIdentity.loadOrCreate(db)
    val signer: SeedSigner = SeedSigner(db.get("self", "device_seed") ?: SeedSigner.newSeed().also { db.put("self", "device_seed", it) })
    private val book = InviteBook()

    private fun selfBlob(k: String, size: Int) = db.get("self", k) ?: ByteArray(size).also { rnd.nextBytes(it); db.put("self", k, it) }
    val mailboxId: ByteArray get() = selfBlob("mailbox_id", 16)
    private val mailboxToken: ByteArray get() = selfBlob("mailbox_token", 32)

    private fun addr(c: Contact) = SignalProtocolAddress(c.signalName, 1)

    /** Idempotent: creates the inbox on the server and keeps prekeys topped up. */
    @Synchronized fun sync() {
        if (db.get("self", "mailbox_created") == null) {
            api.createMailbox(signer, mailboxId, mailboxToken); db.put("self", "mailbox_created", byteArrayOf(1))
        }
        if (db.get("self", "prekeys_uploaded") == null || me.oneTimeKeys().size < 5) {
            me.refill(20)
            api.putPrekeys(signer, me.bundle.serialize(), me.oneTimeKeys().map { it.serialize() })
            db.put("self", "prekeys_uploaded", byteArrayOf(1))
        }
    }

    // ---------------------------------------------------------------- meeting in person
    @Synchronized fun myInvite(replyTo: ByteArray? = null): String =
        book.issue(me.identityKey, signer.publicKey, mailboxId, System.currentTimeMillis() / 1000, replyTo).encode()

    @Synchronized fun acceptInvite(text: String, name: String, confirmChange: Boolean = false): InviteResult {
        val inv = try { Invite.decode(text.trim(), System.currentTimeMillis() / 1000) } catch (e: MalformedException) { return InviteResult.Rejected }
        if (inv.deviceKey.contentEquals(signer.publicKey)) return InviteResult.Rejected
        inv.replyTo?.let { if (!book.redeem(it, System.currentTimeMillis() / 1000)) return InviteResult.Rejected }
        val signalName = inv.deviceKey.hex()
        val a = SignalProtocolAddress(signalName, 1)
        val existing = db.contactBySignalName(signalName)
        if (existing != null && !existing.identity.contentEquals(inv.identity.serialize())) {
            if (!confirmChange) return InviteResult.KeyChanged(existing.name)
            me.store.acceptKeyChange(a, inv.identity)
        } else me.store.pin(a, inv.identity)
        db.saveContact(existing?.name ?: name.ifBlank { signalName.take(8) }, signalName, inv.deviceKey, inv.mailboxId, inv.identity.serialize())
        val reply = if (inv.replyTo == null) book.issue(me.identityKey, signer.publicKey, mailboxId, System.currentTimeMillis() / 1000, inv.nonce).encode() else null
        return InviteResult.Added(db.contactBySignalName(signalName)!!, reply)
    }

    fun safetyNumber(c: Contact): String =
        SafetyNumber.of(signer.publicKey, me.identityKey, c.deviceKey, org.signal.libsignal.protocol.IdentityKey(c.identity))

    // ---------------------------------------------------------------- sending
    private fun send(c: Contact, kind: Kind, payload: ByteArray, ttl: Int) {
        val a = addr(c); val conv = Conversation(me, a)
        if (!me.store.containsSession(a)) {
            val (lt, otp) = api.takePrekeys(signer, c.deviceKey)
            conv.startFrom(LongTermBundle.parse(lt), otp?.let { OneTime.parse(it) })
        }
        api.putPacket(signer, c.mailboxId, conv.seal(Inner(kind, signer.publicKey, System.currentTimeMillis(), ttl, payload)))
    }

    private fun autoDeleteS() = db.setting("autodelete_s", "0").toIntOrNull() ?: 0
    private fun expiry(ttl: Int) = if (ttl > 0) System.currentTimeMillis() + ttl * 1000L else 0L

    @Synchronized fun sendText(c: Contact, text: String) {
        val ttl = autoDeleteS()
        send(c, Kind.TEXT, text.toByteArray(), ttl)
        db.addMessage(c.id, true, Kind.TEXT.code, text, null, null, false, System.currentTimeMillis(), expiry(ttl))
    }

    @Synchronized fun sendFile(c: Contact, data: ByteArray, name: String, voice: Boolean) {
        require(data.size <= MAX_FILE) { "file too large" }
        val ttl = autoDeleteS()
        val (m, chunks) = FileCrypto.encrypt(data, name, voice)
        send(c, Kind.FILE_MANIFEST, m.serialize(), ttl)
        chunks.forEachIndexed { i, ct -> send(c, Kind.FILE_CHUNK, m.fileId + ByteBuffer.allocate(4).putInt(i).array() + ct, ttl) }
        db.addMessage(c.id, true, Kind.FILE_MANIFEST.code, null, data, name, voice, System.currentTimeMillis(), expiry(ttl))
    }

    // ---------------------------------------------------------------- receiving
    /** Fetch, decrypt (trying each contact: the sender is hidden inside the envelope), store, acknowledge. Returns count. */
    @Synchronized fun poll(): Int {
        var n = 0
        for (p in api.fetch(mailboxId, mailboxToken)) {
            if (handle(p.data)) n++
            api.ack(mailboxId, mailboxToken, p.id)   // undecryptable packets are dropped, they would otherwise be retried forever
        }
        if (n > 0 && me.oneTimeKeys().size < 5) sync()
        return n
    }

    private fun handle(envelope: ByteArray): Boolean {
        for (c in db.contacts()) {
            val inner = try { Conversation(me, addr(c)).open(envelope) } catch (e: Exception) { continue }
            if (!inner.senderDeviceKey.contentEquals(c.deviceKey)) return false   // claimed sender does not match the key we decrypted with
            store(c, inner); return true
        }
        return false
    }

    private fun store(c: Contact, m: Inner) {
        val exp = expiry(m.expireAfterS)
        when (m.kind) {
            Kind.TEXT -> db.addMessage(c.id, false, Kind.TEXT.code, String(m.payload), null, null, false, System.currentTimeMillis(), exp)
            Kind.FILE_MANIFEST -> try {
                val man = FileManifest.parse(m.payload)
                if (man.size > MAX_FILE) return
                db.put("manifest", man.fileId.hex(), m.payload); db.put("manifest_meta", man.fileId.hex(), "${c.id}:$exp".toByteArray())
                assemble(man.fileId.hex())
            } catch (e: MalformedException) { }
            Kind.FILE_CHUNK -> {
                if (m.payload.size < 21) return
                val b = ByteBuffer.wrap(m.payload); val id = ByteArray(16).also { b.get(it) }; val idx = b.getInt()
                if (idx < 0 || idx > 100_000) return
                db.put("chunk", "${id.hex()}:$idx", ByteArray(b.remaining()).also { b.get(it) }); assemble(id.hex())
            }
        }
    }

    private fun assemble(idHex: String) {
        val man = FileManifest.parse(db.get("manifest", idHex) ?: return)
        val meta = String(db.get("manifest_meta", idHex) ?: return).split(":")
        val asm = FileAssembler(man)
        for (i in 0 until man.count) db.get("chunk", "$idHex:$i")?.let { asm.accept(i, it) }
        if (asm.missing().isNotEmpty()) return
        val file = try { asm.finish() } catch (e: MalformedException) { return }
        db.addMessage(meta[0].toLong(), false, Kind.FILE_MANIFEST.code, null, file, man.name, man.voice, System.currentTimeMillis(), meta[1].toLong())
        db.delete("manifest", idHex); db.delete("manifest_meta", idHex)
        for (i in 0 until man.count) db.delete("chunk", "$idHex:$i")
    }

    fun listen(onNew: () -> Unit) = api.listen(mailboxId, mailboxToken, onNew)

    fun purgeExpired() = db.purgeExpired(System.currentTimeMillis())
}
