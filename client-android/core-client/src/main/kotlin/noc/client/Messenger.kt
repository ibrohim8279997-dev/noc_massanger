package noc.client

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
private const val DAY = 86_400_000L

/** Glue between storage, crypto and server. All calls block: run them off the main thread. */
class Messenger(private val db: Storage, val api: ServerApi) {
    private val rnd = SecureRandom()
    val me: LocalIdentity = LocalIdentity.loadOrCreate(db)
    val signer: SeedSigner = SeedSigner(db.get("self", "device_seed") ?: SeedSigner.newSeed().also { db.put("self", "device_seed", it) })
    private val book = InviteBook()

    /** Where outgoing envelopes go: straight to the server, or into the constant-rate cover channel. */
    fun interface Outbound { fun send(dest: ByteArray, envelope: ByteArray) }
    @Volatile var outbound: Outbound = Outbound { d, e -> api.putPacket(d, e) }
    /** Random delay before each copy of a group message, so the server cannot link the copies by timing. */
    @Volatile var groupJitterMs: Long = 3000
    @Volatile var sleeper: (Long) -> Unit = { Thread.sleep(it) }
    @Volatile var onChange: () -> Unit = {}

    private fun blob(k: String, size: Int) = db.get("self", k) ?: ByteArray(size).also { rnd.nextBytes(it); db.put("self", k, it) }
    val mailboxId: ByteArray get() = blob("mailbox_id", 16)
    private val mailboxToken: ByteArray get() = blob("mailbox_token", 32)

    /** Mailboxes to download from: the current one, plus the previous one while a rotation is settling. */
    fun receiveBoxes(): List<Pair<ByteArray, ByteArray>> =
        listOfNotNull(mailboxId to mailboxToken, db.get("self", "old_mailbox_id")?.let { it to db.get("self", "old_mailbox_token")!! })

    private fun addr(c: Contact) = SignalProtocolAddress(c.signalName, 1)

    /** Idempotent: creates the inbox on the server and keeps prekeys topped up. */
    @Synchronized fun sync() {
        if (db.get("self", "mailbox_created") == null) {
            try { api.createMailbox(signer, mailboxId, mailboxToken) }
            catch (e: ApiException) { if (e.code != 409) throw e }   // 409: already created by an earlier attempt
            db.put("self", "mailbox_created", byteArrayOf(1))
        }
        if (db.get("self", "prekeys_uploaded") == null || me.oneTimeKeys().size < 5) {
            me.refill(20)
            api.putPrekeys(signer, me.bundle.serialize(), me.oneTimeKeys().map { it.serialize() })
            db.put("self", "prekeys_uploaded", byteArrayOf(1))
        }
    }

    // ---------------------------------------------------------------- mailbox rotation
    /** New mailbox id+token; contacts learn the new id through an encrypted message; the old box lives on for a grace period. */
    @Synchronized fun rotateMailbox(nowMs: Long = System.currentTimeMillis(), graceMs: Long = 2 * DAY) {
        val newId = ByteArray(16).also { rnd.nextBytes(it) }; val newTok = ByteArray(32).also { rnd.nextBytes(it) }
        api.createMailbox(signer, newId, newTok)
        finishRotation(force = true)                                   // an even older box is retired first
        db.put("self", "old_mailbox_id", mailboxId); db.put("self", "old_mailbox_token", mailboxToken)
        db.put("self", "old_until", nowMs.toString().plus(":").plus(graceMs).toByteArray())
        db.put("self", "mailbox_id", newId); db.put("self", "mailbox_token", newTok)
        db.put("self", "rotated_at", nowMs.toString().toByteArray())
        db.contacts().forEach { c -> try { send(c, Kind.MAILBOX_UPDATE, newId, 0) } catch (e: Exception) { } }
    }

    /** Deletes the old mailbox once its grace period is over (or immediately when forced). */
    @Synchronized fun finishRotation(nowMs: Long = System.currentTimeMillis(), force: Boolean = false) {
        val oldId = db.get("self", "old_mailbox_id") ?: return
        val (since, grace) = String(db.get("self", "old_until") ?: return).split(":").map { it.toLong() }
        if (!force && nowMs < since + grace) return
        try { api.deleteMailbox(oldId, db.get("self", "old_mailbox_token")!!) } catch (e: ApiException) { if (e.code != 404) throw e }
        db.delete("self", "old_mailbox_id"); db.delete("self", "old_mailbox_token"); db.delete("self", "old_until")
    }

    /** Called from the background loop: rotate every [everyMs], retire old boxes. */
    @Synchronized fun maintain(nowMs: Long = System.currentTimeMillis(), everyMs: Long = 7 * DAY) {
        finishRotation(nowMs)
        val last = db.get("self", "rotated_at")?.let { String(it).toLong() }
        if (last == null) db.put("self", "rotated_at", nowMs.toString().toByteArray())
        else if (nowMs - last >= everyMs) rotateMailbox(nowMs)
    }

    // ---------------------------------------------------------------- meeting in person
    /** Long-lived card for joining the server: the administrator scans it to add this device as a user. */
    @Synchronized fun deviceCard(): String =
        Invite(me.identityKey, signer.publicKey, mailboxId, ByteArray(16).also { rnd.nextBytes(it) }, null, System.currentTimeMillis() / 1000 + 86_400).encode()

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
            val (lt, otp) = api.takePrekeys(c.deviceKey)
            conv.startFrom(LongTermBundle.parse(lt), otp?.let { OneTime.parse(it) })
        }
        outbound.send(c.mailboxId, conv.seal(Inner(kind, signer.publicKey, System.currentTimeMillis(), ttl, payload)))
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

    // ---------------------------------------------------------------- groups: one separately encrypted copy per member
    private fun members(g: Group): List<Contact> =
        g.members.filter { !it.contentEquals(signer.publicKey) }.mapNotNull { k -> db.contacts().firstOrNull { it.deviceKey.contentEquals(k) } }

    private fun encodeInfo(gid: ByteArray, name: String, keys: List<ByteArray>): ByteArray {
        val n = name.toByteArray()
        val b = ByteBuffer.allocate(16 + 2 + n.size + 2 + 32 * keys.size).put(gid).putShort(n.size.toShort()).put(n).putShort(keys.size.toShort())
        keys.forEach { b.put(it) }
        return b.array()
    }

    private fun spread(targets: List<Contact>, action: (Contact) -> Unit) {
        targets.shuffled(rnd).forEachIndexed { i, c ->
            if (i > 0 && groupJitterMs > 0) sleeper((rnd.nextDouble() * groupJitterMs).toLong())
            action(c)
        }
    }

    @Synchronized fun createGroup(name: String, with: List<Contact>): Group {
        require(with.isNotEmpty() && with.size < 30)
        val gid = ByteArray(16).also { rnd.nextBytes(it) }
        val keys = listOf(signer.publicKey) + with.map { it.deviceKey }
        val rowId = db.saveGroup(gid, name, keys)
        val info = encodeInfo(gid, name, keys)
        spread(with) { send(it, Kind.GROUP_INFO, info, 0) }
        return db.group(rowId)!!
    }

    @Synchronized fun sendGroupText(g: Group, text: String) {
        val ttl = autoDeleteS()
        spread(members(g)) { send(it, Kind.GROUP_TEXT, g.groupId + text.toByteArray(), ttl) }
        db.addMessage(-g.id, true, Kind.TEXT.code, text, null, null, false, System.currentTimeMillis(), expiry(ttl), 0)
    }

    // ---------------------------------------------------------------- receiving
    /** Direct mode: fetch, decrypt, store, acknowledge. */
    @Synchronized fun poll(): Int {
        var n = 0
        for ((mb, tok) in receiveBoxes()) for (p in api.fetch(mb, tok)) {
            if (receive(p.data)) n++
            api.ack(mb, tok, p.id)   // undecryptable packets are dropped, they would otherwise be retried forever
        }
        if (n > 0 && me.oneTimeKeys().size < 5) sync()
        return n
    }

    /** One raw envelope from the server (either mode). The sender is hidden inside, so every contact is tried. */
    @Synchronized fun receive(envelope: ByteArray): Boolean {
        for (c in db.contacts()) {
            val inner = try { Conversation(me, addr(c)).open(envelope) } catch (e: Exception) { continue }
            if (!inner.senderDeviceKey.contentEquals(c.deviceKey)) return false   // claimed sender does not match the key we decrypted with
            store(c, inner); onChange(); return true
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
            Kind.MAILBOX_UPDATE -> if (m.payload.size == 16)
                db.saveContact(c.name, c.signalName, c.deviceKey, m.payload, c.identity)          // authenticated: it came through our session with c
            Kind.GROUP_INFO -> try {
                val b = ByteBuffer.wrap(m.payload); val gid = ByteArray(16).also { b.get(it) }
                val name = String(ByteArray(b.short.toInt() and 0xffff).also { b.get(it) })
                val keys = List(b.short.toInt() and 0xffff) { ByteArray(32).also { k -> b.get(k) } }
                if (keys.size in 2..30 && keys.any { it.contentEquals(signer.publicKey) } && keys.any { it.contentEquals(c.deviceKey) } && db.groupByGroupId(gid) == null)
                    db.saveGroup(gid, name, keys)
            } catch (e: Exception) { }
            Kind.GROUP_TEXT -> {
                if (m.payload.size < 16) return
                val g = db.groupByGroupId(m.payload.copyOfRange(0, 16)) ?: return
                if (g.members.none { it.contentEquals(c.deviceKey) }) return          // not a member: ignore
                db.addMessage(-g.id, false, Kind.TEXT.code, String(m.payload.copyOfRange(16, m.payload.size)), null, null, false, System.currentTimeMillis(), exp, c.id)
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

    // ---------------------------------------------------------------- cover traffic wiring
    /** Switches this messenger to the constant-rate channel: outgoing goes through slots, incoming arrives through slots. */
    fun startCover(mode: () -> CoverMode, activePeriodMs: Long = 2_000, idlePeriodMs: Long = 30_000, activeWindowMs: Long = 180_000, paranoidPeriodMs: Long = 5_000): CoverChannel {
        val ch = CoverChannel(api, { receiveBoxes() }, mode, { receive(it) }, activePeriodMs = activePeriodMs, idlePeriodMs = idlePeriodMs, activeWindowMs = activeWindowMs, paranoidPeriodMs = paranoidPeriodMs)
        outbound = Outbound { d, e -> ch.enqueue(d, e) }
        return ch
    }

    fun listen(onNew: () -> Unit) = api.listen(mailboxId, mailboxToken, onNew)
    fun purgeExpired() = db.purgeExpired(System.currentTimeMillis())
}
