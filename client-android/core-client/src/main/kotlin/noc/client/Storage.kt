package noc.client

import noc.crypto.Kv

class Contact(val id: Long, val name: String, val signalName: String, val deviceKey: ByteArray,
              val mailboxId: ByteArray, val identity: ByteArray)

class Msg(val id: Long, val contactId: Long, val outgoing: Boolean, val kind: Int, val text: String?,
          val fileName: String?, val voice: Boolean, val ts: Long, val expiresAt: Long, val hasFile: Boolean)

class LastMsg(val text: String?, val fileName: String?, val voice: Boolean, val ts: Long, val outgoing: Boolean)

/** Everything the messenger needs to persist. Android: SQLCipher. Tests: memory. */
interface Storage : Kv {
    fun setting(k: String, def: String): String
    fun setSetting(k: String, v: String)
    fun contacts(): List<Contact>
    fun contactBySignalName(n: String): Contact?
    fun contact(id: Long): Contact?
    fun saveContact(name: String, signalName: String, deviceKey: ByteArray, mailboxId: ByteArray, identity: ByteArray)
    fun deleteContact(id: Long)
    fun addMessage(contactId: Long, outgoing: Boolean, kind: Int, text: String?, file: ByteArray?, fileName: String?, voice: Boolean, ts: Long, expiresAt: Long)
    fun messages(contactId: Long): List<Msg>
    fun messageFile(id: Long): ByteArray?
    fun lastMessage(contactId: Long): LastMsg?
    fun unreadCount(contactId: Long, since: Long): Int
    fun purgeExpired(now: Long): Int
}
