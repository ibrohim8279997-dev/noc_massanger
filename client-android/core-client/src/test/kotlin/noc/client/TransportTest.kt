package noc.client

import java.io.DataInputStream
import java.net.ServerSocket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import kotlin.test.*

/** Minimal SOCKS5 proxy that records what the client asked for, then replies with an HTTP answer itself. */
private class FakeSocks : AutoCloseable {
    val ss = ServerSocket(0)
    val requestedHosts = CopyOnWriteArrayList<String>()
    val port get() = ss.localPort
    init {
        thread(isDaemon = true) {
            while (!ss.isClosed) {
                val s = try { ss.accept() } catch (e: Exception) { break }
                thread(isDaemon = true) {
                    try {
                        val i = DataInputStream(s.getInputStream()); val o = s.getOutputStream()
                        i.readByte(); val n = i.readByte().toInt(); i.skipBytes(n); o.write(byteArrayOf(5, 0))
                        i.readByte(); i.readByte(); i.readByte(); val atyp = i.readByte().toInt()
                        val host = if (atyp == 3) { val l = i.readByte().toInt() and 0xff; String(ByteArray(l).also { i.readFully(it) }) } else "ip-address"
                        i.readShort(); requestedHosts.add(host)
                        o.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                        val buf = ByteArray(4096); s.getInputStream().read(buf)
                        o.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".toByteArray()); o.flush(); s.close()
                    } catch (e: Exception) { }
                }
            }
        }
    }
    override fun close() = ss.close()
}

class TransportTest {
    private val onion = "http://abcdefghijklmnop234567abcdefghijklmnop234567abcdefghijklmnopq.onion:80/v1/x"

    @Test fun tor_mode_hands_the_hostname_to_the_proxy_and_never_resolves_it_locally() {
        FakeSocks().use { p ->
            val client = Transport.tor("127.0.0.1", p.port)
            client.newCall(okhttp3.Request.Builder().url(onion).build()).execute().use { assertEquals(200, it.code) }
            assertEquals(listOf("abcdefghijklmnop234567abcdefghijklmnop234567abcdefghijklmnopq.onion"), p.requestedHosts)   // name sent to Tor, unresolved
        }
    }

    @Test fun tor_mode_fails_closed_when_tor_is_down_and_opens_no_direct_connection() {
        val direct = ServerSocket(0); val hits = java.util.concurrent.atomic.AtomicInteger()
        thread(isDaemon = true) { while (!direct.isClosed) { try { direct.accept().close(); hits.incrementAndGet() } catch (e: Exception) { break } } }
        val deadPort = ServerSocket(0).use { it.localPort }                         // nothing listens here: "Tor is down"
        val client = Transport.tor("127.0.0.1", deadPort)
        assertFailsWith<java.io.IOException> { client.newCall(okhttp3.Request.Builder().url("http://127.0.0.1:${direct.localPort}/").build()).execute() }
        assertFailsWith<java.io.IOException> { client.newCall(okhttp3.Request.Builder().url("http://example.com/").build()).execute() }
        Thread.sleep(300); assertEquals(0, hits.get())                              // the "direct" server never saw a connection
        direct.close()
    }

    @Test fun tor_mode_does_not_do_dns_lookups_even_for_ordinary_names() {
        FakeSocks().use { p ->
            val client = Transport.tor("127.0.0.1", p.port)
            client.newCall(okhttp3.Request.Builder().url("http://no-such-host.invalid/").build()).execute().close()
            assertEquals(listOf("no-such-host.invalid"), p.requestedHosts)          // .invalid would fail any local lookup; the proxy got the raw name
        }
    }
}
