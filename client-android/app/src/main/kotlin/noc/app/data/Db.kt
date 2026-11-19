package noc.app.data

import android.content.ContentValues
import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase
import noc.client.*

/** Everything lives in one SQLCipher file. Only parameterized statements: no SQL is built from user data. */
class Db private constructor(private val sql: SQLiteDatabase) : Storage {
    companion object {
        fun open(ctx: Context, key: ByteArray): Db {
            System.loadLibrary("sqlcipher")
            val f = ctx.getDatabasePath("noc.db").also { it.parentFile?.mkdirs() }
            val db = SQLiteDatabase.openOrCreateDatabase(f, key, null, null, null)
            // PRAGMAs that return a row must go through rawQuery: execSQL throws SQLiteException for them on Android
            db.rawQuery("PRAGMA secure_delete = ON", arrayOf<String>()).use { it.moveToFirst() }
            db.execSQL("CREATE TABLE IF NOT EXISTS kv(ns TEXT NOT NULL, k TEXT NOT NULL, v BLOB NOT NULL, PRIMARY KEY(ns,k))")
            db.execSQL("CREATE TABLE IF NOT EXISTS contacts(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, " +
                "signal_name TEXT NOT NULL UNIQUE, device_key BLOB NOT NULL, mailbox_id BLOB NOT NULL, identity BLOB NOT NULL)")
            db.execSQL("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, contact_id INTEGER NOT NULL, " +
                "outgoing INTEGER NOT NULL, kind INTEGER NOT NULL, text TEXT, file BLOB, file_name TEXT, voice INTEGER NOT NULL DEFAULT 0, " +
                "ts INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0)")
            try { db.execSQL("ALTER TABLE messages ADD COLUMN sender INTEGER NOT NULL DEFAULT 0") } catch (_: Exception) { }   // upgrade from stage 1
            db.execSQL("CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY AUTOINCREMENT, group_id BLOB NOT NULL UNIQUE, name TEXT NOT NULL, members BLOB NOT NULL)")
            db.execSQL("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)")
            return Db(db)
        }
    }

    fun close() = sql.close()

    // ---- Kv for libsignal state
    override fun get(ns: String, key: String): ByteArray? =
        sql.rawQuery("SELECT v FROM kv WHERE ns=? AND k=?", arrayOf(ns, key)).use { if (it.moveToFirst()) it.getBlob(0) else null }
    override fun put(ns: String, key: String, value: ByteArray) {
        sql.insertWithOnConflict("kv", null, ContentValues().apply { put("ns", ns); put("k", key); put("v", value) }, SQLiteDatabase.CONFLICT_REPLACE)
    }
    override fun delete(ns: String, key: String) { sql.delete("kv", "ns=? AND k=?", arrayOf(ns, key)) }
    override fun keys(ns: String): List<String> =
        sql.rawQuery("SELECT k FROM kv WHERE ns=?", arrayOf(ns)).use { c -> generateSequence { if (c.moveToNext()) c.getString(0) else null }.toList() }

    // ---- settings
    override fun setting(k: String, def: String): String =
        sql.rawQuery("SELECT v FROM settings WHERE k=?", arrayOf(k)).use { if (it.moveToFirst()) it.getString(0) else def }
    override fun setSetting(k: String, v: String) {
        sql.insertWithOnConflict("settings", null, ContentValues().apply { put("k", k); put("v", v) }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    // ---- contacts
    private fun readContact(c: android.database.Cursor) =
        Contact(c.getLong(0), c.getString(1), c.getString(2), c.getBlob(3), c.getBlob(4), c.getBlob(5))

    override fun contacts(): List<Contact> = sql.rawQuery("SELECT id,name,signal_name,device_key,mailbox_id,identity FROM contacts ORDER BY name", arrayOf<String>())
        .use { c -> generateSequence { if (c.moveToNext()) readContact(c) else null }.toList() }
    override fun contactBySignalName(n: String): Contact? = sql.rawQuery(
        "SELECT id,name,signal_name,device_key,mailbox_id,identity FROM contacts WHERE signal_name=?", arrayOf(n)).use { if (it.moveToFirst()) readContact(it) else null }
    override fun contact(id: Long): Contact? = sql.rawQuery(
        "SELECT id,name,signal_name,device_key,mailbox_id,identity FROM contacts WHERE id=?", arrayOf(id.toString())).use { if (it.moveToFirst()) readContact(it) else null }
    override fun saveContact(name: String, signalName: String, deviceKey: ByteArray, mailboxId: ByteArray, identity: ByteArray) {
        sql.insertWithOnConflict("contacts", null, ContentValues().apply {
            put("name", name); put("signal_name", signalName); put("device_key", deviceKey); put("mailbox_id", mailboxId); put("identity", identity)
        }, SQLiteDatabase.CONFLICT_REPLACE)
    }
    override fun deleteContact(id: Long) { sql.delete("messages", "contact_id=?", arrayOf(id.toString())); sql.delete("contacts", "id=?", arrayOf(id.toString())) }

    // ---- messages
    override fun saveGroup(groupId: ByteArray, name: String, members: List<ByteArray>): Long {
        val packed = java.io.ByteArrayOutputStream().also { o -> members.forEach { o.write(it) } }.toByteArray()
        return sql.insertWithOnConflict("groups", null, ContentValues().apply { put("group_id", groupId); put("name", name); put("members", packed) }, SQLiteDatabase.CONFLICT_REPLACE)
    }
    override fun groups(): List<Group> = sql.rawQuery("SELECT id,group_id,name,members FROM groups ORDER BY name", arrayOf<String>()).use { c ->
        generateSequence { if (c.moveToNext()) { val m = c.getBlob(3); Group(c.getLong(0), c.getBlob(1), c.getString(2), (0 until m.size / 32).map { m.copyOfRange(it * 32, it * 32 + 32) }) } else null }.toList() }
    override fun addMessage(contactId: Long, outgoing: Boolean, kind: Int, text: String?, file: ByteArray?, fileName: String?,
                   voice: Boolean, ts: Long, expiresAt: Long, senderId: Long) {
        sql.insert("messages", null, ContentValues().apply {
            put("sender", senderId)
            put("contact_id", contactId); put("outgoing", if (outgoing) 1 else 0); put("kind", kind); put("text", text)
            if (file != null) put("file", file); put("file_name", fileName); put("voice", if (voice) 1 else 0)
            put("ts", ts); put("expires_at", expiresAt)
        })
    }
    override fun messages(contactId: Long): List<Msg> = sql.rawQuery(
        "SELECT id,contact_id,outgoing,kind,text,file_name,voice,ts,expires_at,file IS NOT NULL,sender FROM messages WHERE contact_id=? ORDER BY ts, id",
        arrayOf(contactId.toString())).use { c -> generateSequence {
            if (c.moveToNext()) Msg(c.getLong(0), c.getLong(1), c.getInt(2) == 1, c.getInt(3), c.getString(4), c.getString(5),
                c.getInt(6) == 1, c.getLong(7), c.getLong(8), c.getInt(9) == 1, c.getLong(10)) else null }.toList() }
    override fun messageFile(id: Long): ByteArray? = sql.rawQuery("SELECT file FROM messages WHERE id=?", arrayOf(id.toString())).use { if (it.moveToFirst()) it.getBlob(0) else null }
    override fun lastMessage(contactId: Long): LastMsg? = sql.rawQuery(
        "SELECT text,file_name,voice,ts,outgoing FROM messages WHERE contact_id=? ORDER BY ts DESC, id DESC LIMIT 1",
        arrayOf(contactId.toString())).use { if (it.moveToFirst()) LastMsg(it.getString(0), it.getString(1), it.getInt(2) == 1, it.getLong(3), it.getInt(4) == 1) else null }
    override fun unreadCount(contactId: Long, since: Long): Int = sql.rawQuery(
        "SELECT COUNT(*) FROM messages WHERE contact_id=? AND outgoing=0 AND ts>?", arrayOf(contactId.toString(), since.toString())).use { it.moveToFirst(); it.getInt(0) }
    fun lastMessageTs(contactId: Long): Long = sql.rawQuery("SELECT COALESCE(MAX(ts),0) FROM messages WHERE contact_id=?", arrayOf(contactId.toString())).use { it.moveToFirst(); it.getLong(0) }
    override fun purgeExpired(now: Long): Int = sql.delete("messages", "expires_at>0 AND expires_at<=?", arrayOf(now.toString()))
    fun wipeAll() { sql.execSQL("DELETE FROM messages"); sql.execSQL("DELETE FROM contacts"); sql.execSQL("DELETE FROM kv"); sql.execSQL("DELETE FROM settings") }
}
