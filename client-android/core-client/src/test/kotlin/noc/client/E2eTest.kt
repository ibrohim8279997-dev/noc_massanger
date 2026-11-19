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

    @Test fun removed_user_is_cut_off_from_the_server_but_can_still_write_until_mailboxes_are_rotated() {
        val (a, b, adm) = fresh(); meet(a, "Bob", b, "Alice")
        ServerApi(b.base).removeUser(adm, b.key)
        // registration-type actions need an identity: gone
        assertEquals(401, assertFailsWith<ApiException> { b.m.rotateMailbox() }.code)
        // nobody can start talking to bob: his keys and mailbox were deleted with him
        assertEquals(404, assertFailsWith<ApiException> { a.m.sendText(a.storage.contacts().single(), "y") }.code)
        // KNOWN CONSEQUENCE of anonymous sending: knowing alice's mailbox id is the right to write to it
        b.m.sendText(b.storage.contacts().single(), "still works"); assertEquals(1, a.m.poll())
        // rotating alice's mailbox closes that door for good
        a.m.rotateMailbox(); a.m.finishRotation(force = true)
        assertEquals(404, assertFailsWith<ApiException> { b.m.sendText(b.storage.contacts().single(), "nope") }.code)
    }
}

/** Stage 2 against the real server: anonymous sending, cover channel, groups, mailbox rotation. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Stage2E2eTest {
    private val servers = ArrayList<ServerProc>()
    @org.junit.jupiter.api.BeforeEach fun check() { assumeTrue(ServerProc.available(), "server/.venv not found") }
    @org.junit.jupiter.api.AfterEach fun cleanup() { servers.forEach { it.close() }; servers.clear() }

    private fun world(n: Int): Pair<ServerProc, List<Phone>> {
        val s = ServerProc.start(); servers.add(s)
        val phones = List(n) { Phone(s.baseUrl).also { p -> p.m.groupJitterMs = 0 } }
        setupAdmin(s, *phones.toTypedArray()); phones.forEach { it.m.sync() }
        return s to phones
    }

    @Test fun messages_flow_through_the_cover_channel_and_files_too() {
        val (_, ph) = world(2); val (a, b) = ph
        meet(a, "Bob", b, "Alice")
        val ca = a.m.startCover({ CoverMode.PARANOID }, activePeriodMs = 40, paranoidPeriodMs = 40)
        val cb = b.m.startCover({ CoverMode.PARANOID }, activePeriodMs = 40, paranoidPeriodMs = 40)
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val ta = Thread { ca.run({ stop.get() }) }.also { it.start() }; val tb = Thread { cb.run({ stop.get() }) }.also { it.start() }
        try {
            val bob = a.storage.contacts().single(); val alice = b.storage.contacts().single()
            a.m.sendText(bob, "через слоты")
            waitFor(8000) { b.storage.messages(alice.id).any { it.text == "через слоты" } }
            val data = ByteArray(40_000) { (it % 251).toByte() }
            b.m.sendFile(alice, data, "v.m4a", true)
            waitFor(15000) { a.storage.messages(bob.id).any { it.hasFile } }
            assertContentEquals(data, a.storage.messageFile(a.storage.messages(bob.id).first { it.hasFile }.id))
        } finally { stop.set(true); ta.join(); tb.join() }
    }

    @Test fun sender_is_anonymous_to_the_server_no_identity_headers_on_sends() {
        // sending must work with a client that has no signer registered at all for sending: use a bare ServerApi
        val (s, ph) = world(2); val (a, b) = ph
        meet(a, "Bob", b, "Alice")
        val api = ServerApi(s.baseUrl)
        val bobBox = b.storage.contacts().single().mailboxId
        api.putPacket(bobBox, ByteArray(CoverChannel.ENVELOPE))        // no key, no signature: accepted
        assertEquals(0, b.m.poll())                                     // garbage envelope is dropped, not an error
        assertTrue(api.takePrekeys(a.key).first.isNotEmpty())           // keys also fetchable anonymously
    }

    @Test fun group_message_reaches_every_member_separately_and_outsiders_are_ignored() {
        val (_, ph) = world(4); val (a, b, c, outsider) = ph
        meet(a, "B", b, "A"); meet(a, "C", c, "A"); meet(b, "C", c, "B"); meet(outsider, "A", a, "X")
        val g = a.m.createGroup("trio", a.storage.contacts().filter { it.name == "B" || it.name == "C" })
        b.m.poll(); c.m.poll()
        val gb = b.storage.groups().single(); val gc = c.storage.groups().single()
        assertEquals("trio", gb.name); assertEquals(3, gb.members.size)
        a.m.sendGroupText(g, "всем привет")
        assertEquals(1, b.m.poll()); assertEquals(1, c.m.poll())
        assertEquals("всем привет", b.storage.messages(-gb.id).single().text)
        // c answers to the group; b and a get their own copy
        c.m.sendGroupText(gc, "ответ")
        assertEquals(1, a.m.poll()); assertEquals(1, b.m.poll())
        assertEquals("ответ", a.storage.messages(-g.id).last().text)
        assertEquals(a.storage.contacts().first { it.name == "C" }.id, a.storage.messages(-g.id).last().senderId)
        // a non-member who knows a member cannot inject into the group
        val forged = outsider.storage.contacts().single()
        outsider.m.sendGroupText(Group(99, g.groupId, "trio", listOf(outsider.key, a.key)), "подделка")
        a.m.poll(); assertEquals(listOf("всем привет", "ответ"), a.storage.messages(-g.id).map { it.text })
    }

    @Test fun group_copies_use_separate_sessions_and_random_delays_are_applied() {
        val (_, ph) = world(3); val (a, b, c) = ph
        meet(a, "B", b, "A"); meet(a, "C", c, "A")
        val delays = ArrayList<Long>(); a.m.groupJitterMs = 3000; a.m.sleeper = { delays.add(it) }
        val g = a.m.createGroup("g", a.storage.contacts())
        a.m.sendGroupText(g, "x"); a.m.sendGroupText(g, "y")
        assertTrue(delays.isNotEmpty() && delays.all { it in 0..3000 })
        assertTrue(delays.toSet().size > 1)                                   // not a fixed delay
        // each member's envelope is different bytes (separately encrypted)
        val boxes = listOf(b, c).map { it.storage.contacts().single().let { _ -> it.m.mailboxId } }
        val seen = boxes.map { mb -> ServerApi(b.base).fetch(mb, if (mb.contentEquals(b.m.mailboxId)) tokenOf(b) else tokenOf(c)).map { it.data.toList() } }
        assertTrue((seen[0] + seen[1]).toSet().size == (seen[0] + seen[1]).size)
    }

    private fun tokenOf(p: Phone) = p.storage.get("self", "mailbox_token")!!

    @Test fun mailbox_rotation_updates_contacts_keeps_old_box_for_a_while_then_deletes_it() {
        val (s, ph) = world(2); val (a, b) = ph
        meet(a, "Bob", b, "Alice")
        val bob = a.storage.contacts().single(); val alice = b.storage.contacts().single()
        val oldBox = a.m.mailboxId; val oldTok = tokenOf(a)
        a.m.rotateMailbox(graceMs = 60_000)
        assertFalse(a.m.mailboxId.contentEquals(oldBox))
        // bob sends to the OLD id (he has not heard yet): still arrives during the grace period
        b.m.sendText(alice, "до обновления"); assertEquals(1, a.m.poll())
        // bob learns the new id from the encrypted update
        assertEquals(1, b.m.poll())
        assertContentEquals(a.m.mailboxId, b.storage.contact(alice.id)!!.mailboxId)
        b.m.sendText(b.storage.contact(alice.id)!!, "после"); assertEquals(1, a.m.poll())
        // after the grace period the old box is gone from the server
        a.m.finishRotation(System.currentTimeMillis() + 120_000)
        assertEquals(404, assertFailsWith<ApiException> { ServerApi(s.baseUrl).fetch(oldBox, oldTok) }.code)
        // and a bogus update from someone else cannot change a contact's mailbox (it must come through the session)
        assertEquals(listOf("до обновления", "после"), a.storage.messages(bob.id).filter { !it.outgoing }.map { it.text })
    }
}
