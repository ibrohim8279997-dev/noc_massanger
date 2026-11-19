package noc.mesh

import noc.client.*
import noc.crypto.*
import org.signal.libsignal.protocol.SignalProtocolAddress
import java.security.SecureRandom

fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

/** Memory Storage for offline tests (the mesh needs no server). */
class OfflineStorage : Storage {
    private val kv = MemoryKv(); private val settings = HashMap<String, String>()
    private val contacts = ArrayList<Contact>(); private var next = 1L
    class M(val m: Msg, val file: ByteArray?); private val msgs = ArrayList<M>(); private val groups = ArrayList<Group>()
    override fun get(ns: String, key: String) = kv.get(ns, key); override fun put(ns: String, key: String, value: ByteArray) = kv.put(ns, key, value)
    override fun delete(ns: String, key: String) = kv.delete(ns, key); override fun keys(ns: String) = kv.keys(ns)
    override fun setting(k: String, def: String) = settings[k] ?: def; override fun setSetting(k: String, v: String) { settings[k] = v }
    override fun contacts() = contacts.toList(); override fun contactBySignalName(n: String) = contacts.firstOrNull { it.signalName == n }
    override fun contact(id: Long) = contacts.firstOrNull { it.id == id }
    override fun saveContact(name: String, signalName: String, deviceKey: ByteArray, mailboxId: ByteArray, identity: ByteArray) {
        val old = contactBySignalName(signalName); contacts.removeAll { it.signalName == signalName }; contacts.add(Contact(old?.id ?: next++, name, signalName, deviceKey, mailboxId, identity)) }
    override fun deleteContact(id: Long) { contacts.removeAll { it.id == id } }
    override fun addMessage(contactId: Long, outgoing: Boolean, kind: Int, text: String?, file: ByteArray?, fileName: String?, voice: Boolean, ts: Long, expiresAt: Long, senderId: Long) {
        msgs.add(M(Msg(next++, contactId, outgoing, kind, text, fileName, voice, ts, expiresAt, file != null, senderId), file)) }
    override fun messages(contactId: Long) = msgs.filter { it.m.contactId == contactId }.map { it.m }
    override fun messageFile(id: Long) = msgs.firstOrNull { it.m.id == id }?.file
    override fun lastMessage(contactId: Long) = null
    override fun unreadCount(contactId: Long, since: Long) = 0
    override fun purgeExpired(now: Long) = 0
    override fun saveGroup(groupId: ByteArray, name: String, members: List<ByteArray>): Long { val g = Group(next++, groupId, name, members); groups.add(g); return g.id }
    override fun groups() = groups.toList()
}

/** A phone with real crypto and no network at all. */
class Dev(val name: String) {
    val storage = OfflineStorage()
    val m = Messenger(storage, ServerApi("http://127.0.0.1:1", Transport.direct()))   // never used: everything here is offline
    lateinit var node: MeshNode
    val nodeKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

    fun joinMesh(clock: () -> Long, limits: Limits = Limits(), store: EnvelopeStore = EncryptedMemoryStore(nodeKey)) {
        node = MeshNode(MeshCircle(m.circleKey), store, clock, { ct -> m.receiveCiphertext(ct) }, limits)
        m.meshOut = { ct -> node.inject(ct) }
    }
    /** a mere relay: has the circle key but no conversations, so it can carry but never read */
    fun contactOf(other: Dev) = storage.contacts().first { it.deviceKey.contentEquals(other.m.signer.publicKey) }
}

/** Two people meet (QR in both directions) and have a session, as if they had chatted through the server before. */
fun meetOffline(a: Dev, b: Dev) {
    val first = a.m.myInvite()
    val r = b.m.acceptInvite(first, a.name) as InviteResult.Added
    check(a.m.acceptInvite(r.replyInvite!!, b.name) is InviteResult.Added)
    Conversation(a.m.me, SignalProtocolAddress(hex(b.m.signer.publicKey), 1)).startFrom(b.m.me.bundle, b.m.me.oneTimeKeys().first())
}

private val rnd = SecureRandom()

/** One radio encounter between two nodes: the real message codec, optional loss. Returns how many messages crossed. */
fun encounter(a: MeshNode, b: MeshNode, lose: (MeshMsg) -> Boolean = { false }): Int {
    val la = "peer-" + hex(ByteArray(6).also { rnd.nextBytes(it) }); val lb = "peer-" + hex(ByteArray(6).also { rnd.nextBytes(it) })   // throw-away labels
    var crossed = 0
    val toB = ArrayDeque<MeshMsg>().apply { add(a.begin(lb)) }; val toA = ArrayDeque<MeshMsg>().apply { add(b.begin(la)) }
    var guard = 0
    while ((toA.isNotEmpty() || toB.isNotEmpty()) && guard++ < 10_000) {
        toB.removeFirstOrNull()?.let { m -> val w = MeshMsg.decode(m.encode()) ?: return@let; crossed++; if (!lose(w)) b.handle(la, w).forEach { toA.add(it) } }
        toA.removeFirstOrNull()?.let { m -> val w = MeshMsg.decode(m.encode()) ?: return@let; crossed++; if (!lose(w)) a.handle(lb, w).forEach { toB.add(it) } }
    }
    a.end(lb); b.end(la)
    return crossed
}

/** Walks an object graph looking for a byte pattern or text. Used to prove that no trace of something is kept in memory. */
fun deepContains(root: Any?, needle: ByteArray, needleText: String? = null): Boolean {
    val seen = java.util.IdentityHashMap<Any, Boolean>()
    fun walk(o: Any?, depth: Int): Boolean {
        if (o == null || depth > 12 || seen.put(o, true) != null) return false
        when (o) {
            is ByteArray -> return indexOf(o, needle) >= 0 || (needleText != null && String(o, Charsets.ISO_8859_1).contains(needleText))
            is String -> return needleText != null && o.contains(needleText)
            is Number, is Boolean, is Char, is Enum<*>, is Class<*> -> return false
            is Map<*, *> -> return o.entries.any { walk(it.key, depth + 1) || walk(it.value, depth + 1) }
            is Iterable<*> -> return o.any { walk(it, depth + 1) }
            is Array<*> -> return o.any { walk(it, depth + 1) }
        }
        if (o.javaClass.name.startsWith("java.") || o.javaClass.name.startsWith("javax.") || o.javaClass.name.startsWith("jdk.")) return false
        var c: Class<*>? = o.javaClass
        while (c != null && c != Any::class.java) {
            for (f in c.declaredFields) { if (java.lang.reflect.Modifier.isStatic(f.modifiers)) continue
                try { f.isAccessible = true; if (walk(f.get(o), depth + 1)) return true } catch (e: Exception) { } }
            c = c.superclass
        }
        return false
    }
    return walk(root, 0)
}
private fun indexOf(h: ByteArray, n: ByteArray): Int { if (n.isEmpty() || h.size < n.size) return -1; outer@ for (i in 0..h.size - n.size) { for (j in n.indices) if (h[i + j] != n[j]) continue@outer; return i }; return -1 }
