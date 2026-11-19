package noc.client

import noc.crypto.MemoryKv
import noc.crypto.SeedSigner
import java.io.File
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicReference

/** In-memory Storage for JVM tests. */
class MemoryStorage : Storage {
    private val kv = MemoryKv()
    private val settings = HashMap<String, String>()
    private val contacts = ArrayList<Contact>()
    class M(val m: Msg, val file: ByteArray?)
    private val msgs = ArrayList<M>()
    private var nextId = 1L
    override fun get(ns: String, key: String) = kv.get(ns, key)
    override fun put(ns: String, key: String, value: ByteArray) = kv.put(ns, key, value)
    override fun delete(ns: String, key: String) = kv.delete(ns, key)
    override fun keys(ns: String) = kv.keys(ns)
    override fun setting(k: String, def: String) = settings[k] ?: def
    override fun setSetting(k: String, v: String) { settings[k] = v }
    override fun contacts() = contacts.toList()
    override fun contactBySignalName(n: String) = contacts.firstOrNull { it.signalName == n }
    override fun contact(id: Long) = contacts.firstOrNull { it.id == id }
    override fun saveContact(name: String, signalName: String, deviceKey: ByteArray, mailboxId: ByteArray, identity: ByteArray) {
        val old = contactBySignalName(signalName); contacts.removeAll { it.signalName == signalName }
        contacts.add(Contact(old?.id ?: nextId++, name, signalName, deviceKey, mailboxId, identity))
    }
    override fun deleteContact(id: Long) { contacts.removeAll { it.id == id }; msgs.removeAll { it.m.contactId == id } }
    override fun addMessage(contactId: Long, outgoing: Boolean, kind: Int, text: String?, file: ByteArray?, fileName: String?, voice: Boolean, ts: Long, expiresAt: Long, senderId: Long) {
        msgs.add(M(Msg(nextId++, contactId, outgoing, kind, text, fileName, voice, ts, expiresAt, file != null, senderId), file))
    }
    private val groups = ArrayList<Group>()
    override fun saveGroup(groupId: ByteArray, name: String, members: List<ByteArray>): Long { val g = Group(nextId++, groupId, name, members); groups.add(g); return g.id }
    override fun groups() = groups.toList()
    override fun messages(contactId: Long) = msgs.filter { it.m.contactId == contactId }.map { it.m }
    override fun messageFile(id: Long) = msgs.firstOrNull { it.m.id == id }?.file
    override fun lastMessage(contactId: Long) = messages(contactId).lastOrNull()?.let { LastMsg(it.text, it.fileName, it.voice, it.ts, it.outgoing) }
    override fun unreadCount(contactId: Long, since: Long) = messages(contactId).count { !it.outgoing && it.ts > since }
    override fun purgeExpired(now: Long): Int { val n = msgs.size; msgs.removeAll { it.m.expiresAt in 1..now }; return n - msgs.size }
    fun all() = msgs.map { it.m }
}

/** Starts the real Python server from ../../server in a child process. */
class ServerProc private constructor(val baseUrl: String, val bindToken: String, private val proc: Process, val output: StringBuffer) : AutoCloseable {
    override fun close() { proc.destroy(); proc.waitFor() }

    companion object {
        private fun repoServerDir(): File? {
            var d: File? = File("").absoluteFile
            while (d != null) { File(d, "server/.venv/bin/python").takeIf { it.exists() }?.let { return File(d, "server") }; d = d.parentFile }
            return null
        }
        fun available() = repoServerDir() != null

        fun start(extraEnv: Map<String, String> = emptyMap(), extraArgs: List<String> = emptyList()): ServerProc {
            val dir = repoServerDir()!!
            val tmp = java.nio.file.Files.createTempDirectory("noc-e2e").toFile()
            val key = File(tmp, "key").also { it.writeText("ab".repeat(32)) }
            val port = ServerSocket(0).use { it.localPort }
            val pb = ProcessBuilder(File(dir, ".venv/bin/python").path, "-m", "app.cli", "serve", "--host", "127.0.0.1", "--port", "$port", *extraArgs.toTypedArray())
                .directory(dir).redirectErrorStream(true)
            pb.environment().putAll(mapOf("NOC_DB_PATH" to File(tmp, "noc.db").path, "NOC_DB_KEY_FILE" to key.path, "PYTHONUNBUFFERED" to "1") + extraEnv)
            val proc = pb.start()
            val out = StringBuffer(); val token = AtomicReference<String?>()
            Thread { proc.inputStream.bufferedReader().forEachLine { l -> out.append(l).append('\n'); Regex("^[0-9a-f]{64}$").find(l.trim())?.let { token.set(it.value) } } }.apply { isDaemon = true }.start()
            val base = "http://127.0.0.1:$port"
            val http = okhttp3.OkHttpClient()
            val deadline = System.currentTimeMillis() + 20_000
            while (System.currentTimeMillis() < deadline) {
                try { http.newCall(okhttp3.Request.Builder().url("$base/x").build()).execute().close(); break } catch (e: Exception) { Thread.sleep(150) }
            }
            while (token.get() == null && System.currentTimeMillis() < deadline) Thread.sleep(50)
            return ServerProc(base, token.get() ?: error("server did not print a token: $out"), proc, out)
        }
    }
}

/** One simulated phone. */
class Phone(val base: String, val storage: MemoryStorage = MemoryStorage(), makeApi: (String) -> ServerApi = { ServerApi(it, Transport.direct()) }) {
    private val mk = makeApi
    var m = Messenger(storage, mk(base))
    /** "Restart the app": same storage, new objects. */
    fun restart() { m = Messenger(storage, mk(base)) }
    val key get() = m.signer.publicKey
}

fun waitFor(ms: Long = 5000, cond: () -> Boolean) {
    val end = System.currentTimeMillis() + ms
    while (!cond()) { if (System.currentTimeMillis() > end) error("timeout"); Thread.sleep(50) }
}

/** admin binds, then registers the given phones as users */
fun setupAdmin(server: ServerProc, vararg phones: Phone): SeedSigner {
    val admin = SeedSigner(SeedSigner.newSeed())
    val api = ServerApi(server.baseUrl, Transport.direct())
    api.bindSuperadmin(server.bindToken, admin.publicKey)
    phones.forEach { api.addUser(admin, it.key) }
    return admin
}

fun meet(a: Phone, nameOfB: String, b: Phone, nameOfA: String) {
    val first = a.m.myInvite()
    val r = b.m.acceptInvite(first, nameOfA) as InviteResult.Added
    val reply = r.replyInvite!!
    check(a.m.acceptInvite(reply, nameOfB) is InviteResult.Added)
}
