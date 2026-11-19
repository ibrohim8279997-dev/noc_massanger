package noc.client

import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import kotlin.test.*

/** Real server process + real client logic. Skipped if server/.venv is missing. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class E2eTest {
    private var server: ServerProc? = null
    private lateinit var admin: noc.crypto.SeedSigner

    @BeforeAll fun up() { assumeTrue(ServerProc.available(), "server/.venv not found"); server = ServerProc.start() }
    @AfterAll fun down() { server?.close() }

    private fun fresh(): Triple<Phone, Phone, noc.crypto.SeedSigner> {
        // every test uses its own server so tests do not depend on each other
        val s = ServerProc.start(); extra.add(s)
        val a = Phone(s.baseUrl); val b = Phone(s.baseUrl)
        val adm = setupAdmin(s, a, b)
        a.m.sync(); b.m.sync()
        return Triple(a, b, adm)
    }
    private val extra = ArrayList<ServerProc>()
    @org.junit.jupiter.api.AfterEach fun cleanup() { extra.forEach { it.close() }; extra.clear() }

    @Test fun text_roundtrip_both_ways_and_file_and_voice() {
        val (a, b, _) = fresh()
        meet(a, "Bob", b, "Alice")
        val bob = a.storage.contacts().single(); val alice = b.storage.contacts().single()
        a.m.sendText(bob, "привет"); assertEquals(1, b.m.poll())
        assertEquals("привет", b.storage.messages(alice.id).single().text)
        b.m.sendText(alice, "hi"); assertEquals(1, a.m.poll())
        val data = ByteArray(60_000) { (it * 7).toByte() }
        a.m.sendFile(bob, data, "memo.m4a", voice = true)
        var got = 0; repeat(10) { got += b.m.poll() }
        val file = b.storage.messages(alice.id).first { it.hasFile }
        assertTrue(file.voice); assertEquals("memo.m4a", file.fileName)
        assertContentEquals(data, b.storage.messageFile(file.id))
    }

    @Test fun device_not_registered_gets_401_then_works_by_itself_after_admin_adds_it_even_after_restart() {
        val s = ServerProc.start(); extra.add(s)
        val admin = Phone(s.baseUrl); val late = Phone(s.baseUrl)
        val adm = setupAdmin(s, admin); admin.m.sync()
        val e = assertFailsWith<ApiException> { late.m.sync() }
        assertEquals(401, e.code)
        late.restart()                                         // app closed and reopened while waiting
        assertEquals(401, assertFailsWith<ApiException> { late.m.sync() }.code)
        ServerApi(s.baseUrl).addUser(adm, late.key)            // administrator scans the card
        late.m.sync()                                          // the loop does this every cycle
        late.restart(); late.m.sync()                          // and it survives another restart
        meet(admin, "Late", late, "Admin")
        admin.m.sendText(admin.storage.contacts().single(), "welcome"); assertEquals(1, late.m.poll())
    }

    @Test fun sending_to_a_contact_who_never_completed_setup_is_a_clear_404() {
        val s = ServerProc.start(); extra.add(s)
        val a = Phone(s.baseUrl); val ghost = Phone(s.baseUrl)
        val adm = setupAdmin(s, a, ghost); a.m.sync()           // ghost registered but never synced: no mailbox, no prekeys
        meet(a, "Ghost", ghost, "A")
        assertEquals(404, assertFailsWith<ApiException> { a.m.sendText(a.storage.contacts().single(), "x") }.code)
    }

    @Test fun conversation_continues_after_both_apps_restart() {
        val (a, b, _) = fresh(); meet(a, "Bob", b, "Alice")
        val bob = a.storage.contacts().single(); val alice = b.storage.contacts().single()
        a.m.sendText(bob, "1"); b.m.poll()
        a.restart(); b.restart()
        b.m.sendText(b.storage.contacts().single(), "2"); a.m.poll()
        a.m.sendText(a.storage.contacts().single(), "3"); assertEquals(1, b.m.poll())
        assertEquals(listOf("1", "3"), b.storage.messages(alice.id).filter { !it.outgoing }.map { it.text })
    }

    @Test fun removed_user_loses_mailbox_and_cannot_send() {
        val (a, b, adm) = fresh(); meet(a, "Bob", b, "Alice")
        ServerApi(b.base).removeUser(adm, b.key)
        assertEquals(401, assertFailsWith<ApiException> { b.m.sendText(b.storage.contacts().single(), "x") }.code)
        assertEquals(404, assertFailsWith<ApiException> { a.m.sendText(a.storage.contacts().single(), "y") }.code)   // bob's prekeys and mailbox are gone
    }
}
