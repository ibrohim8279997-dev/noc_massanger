package noc.client

import okhttp3.Dns
import okhttp3.OkHttpClient
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.time.Duration

/**
 * How the app reaches the server.
 * Tor mode is fail-closed: everything goes through the local Tor SOCKS port, names are never resolved on this phone
 * (so no DNS request leaves it), and if Tor is not there the request fails instead of going out directly.
 */
object Transport {
    /** Resolving locally is forbidden: the SOCKS proxy (Tor) resolves .onion names itself. */
    private object NoLocalDns : Dns {
        override fun lookup(hostname: String): List<InetAddress> = throw IOException("local DNS lookup is forbidden in Tor mode")
    }

    fun direct(): OkHttpClient = base().build()

    fun tor(socksHost: String = "127.0.0.1", socksPort: Int = 9050): OkHttpClient = base()
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort)))
        .dns(NoLocalDns)
        .proxySelector(object : java.net.ProxySelector() {                 // never fall back to another route
            override fun select(uri: java.net.URI?) = listOf(Proxy(Proxy.Type.SOCKS, InetSocketAddress(socksHost, socksPort)))
            override fun connectFailed(uri: java.net.URI?, sa: java.net.SocketAddress?, ioe: IOException?) {}
        })
        .retryOnConnectionFailure(false)
        .build()

    private fun base() = OkHttpClient.Builder().connectTimeout(Duration.ofSeconds(45)).readTimeout(Duration.ofSeconds(60))
}
