package noc.client

import noc.crypto.Kv

class Contact(val id: Long, val name: String, val signalName: String, val deviceKey: ByteArray,
              val mailboxId: ByteArray, val identity: ByteArray)

/** Group conversations use contact_id = -group.id in the message table. senderId: contact id, 0 = me. */
class Msg(val id: Long, val contactId: Long, val outgoing: Boolean, val kind: Int, val text: String?,
          val fileName: String?, val voice: Boolean, val ts: Long, val expiresAt: Long, val hasFile: Boolean, val senderId: Long = 0)

class LastMsg(val text: String?, val fileName: String?, val voice: Boolean, val ts: Long, val outgoing: Boolean)

class Group(val id: Long, val groupId: ByteArray, val name: String, val members: List<ByteArray>)

/** Everything the messenger needs to persist. Android: SQLCipher. Tests: memory. */
interface Storage : Kv {
    fun setting(k: String, def: String): String
    fun setSetting(k: String, v: String)
    fun contacts(): List<Contact>
    fun contactBySignalName(n: String): Contact?
    fun contact(id: Long): Contact?
    fun saveContact(name: String, signalName: String, deviceKey: ByteArray, mailboxId: ByteArray, identity: ByteArray)
    fun deleteContact(id: Long)
    fun addMessage(contactId: Long, outgoing: Boolean, kind: Int, text: String?, file: ByteArray?, fileName: String?, voice: Boolean, ts: Long, expiresAt: Long, senderId: Long = 0)
    fun messages(contactId: Long): List<Msg>
    fun messageFile(id: Long): ByteArray?
    fun lastMessage(contactId: Long): LastMsg?
    fun unreadCount(contactId: Long, since: Long): Int
    fun purgeExpired(now: Long): Int
    fun saveGroup(groupId: ByteArray, name: String, members: List<ByteArray>): Long
    fun groups(): List<Group>
    fun groupByGroupId(groupId: ByteArray): Group? = groups().firstOrNull { it.groupId.contentEquals(groupId) }
    fun group(id: Long): Group? = groups().firstOrNull { it.id == id }
}
