package noc.app.mesh

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WpsInfo
import android.net.wifi.p2p.*
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceInfo
import android.net.wifi.p2p.nsd.WifiP2pDnsSdServiceRequest
import android.os.Handler
import android.os.Looper
import noc.mesh.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import kotlin.concurrent.thread

/**
 * Wi-Fi Direct (platform API, no Google services) for big files. NOT TESTED ON DEVICES.
 * Discovery: a local DNS-SD service whose instance name is the rotating, circle-derived identifier (same as the BLE one);
 * phones only connect to instances they can compute. Data: a TCP socket inside the P2P group, framed with [FrameStream],
 * run through the shared, tested [MeshSession] (circle authentication first).
 * PRIVACY: Wi-Fi Direct discovery exposes the phone's device name and a (per-connection randomised) MAC to nearby phones.
 * The app cannot hide it, so this transport is off unless the user turns it on.
 */
@SuppressLint("MissingPermission")
class WifiDirectMesh(private val ctx: Context, private val node: MeshNode, private val circleKey: ByteArray, private val clock: () -> Long = System::currentTimeMillis) {
    private val planner = AdvertPlanner(MeshCircle(circleKey))
    private val main = Handler(Looper.getMainLooper())
    private val p2p = ctx.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    private var channel: WifiP2pManager.Channel? = null
    private val rnd = SecureRandom()
    @Volatile private var running = false
    @Volatile private var busy = false
    @Volatile var sessions = 0; private set
    private val port = 8988

    fun available() = p2p != null

    fun start() {
        val m = p2p ?: return
        if (running) return
        running = true
        channel = m.initialize(ctx, Looper.getMainLooper(), null)
        ctx.registerReceiver(receiver, IntentFilter(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION), Context.RECEIVER_NOT_EXPORTED)
        rotate()
    }

    fun stop() {
        running = false; main.removeCallbacksAndMessages(null)
        runCatching { ctx.unregisterReceiver(receiver) }
        val ch = channel; val m = p2p
        if (m != null && ch != null) { m.clearLocalServices(ch, null); m.clearServiceRequests(ch, null); m.removeGroup(ch, null) }
        channel = null; busy = false
    }

    private fun instance(slot: ByteArray) = slot.joinToString("") { "%02x".format(it) }.take(24)

    private fun rotate() {
        val m = p2p ?: return; val ch = channel ?: return
        if (!running) return
        val now = clock()
        m.clearLocalServices(ch, null)
        m.addLocalService(ch, WifiP2pDnsSdServiceInfo.newInstance(instance(planner.advertise(now).serviceUuid), "_noc._tcp", emptyMap()), null)
        val wanted = planner.scanFor(now).map { instance(it) }.toSet()
        m.setDnsSdResponseListeners(ch, { name, _, device -> if (name in wanted) connectTo(device) }, null)
        m.clearServiceRequests(ch, null)
        m.addServiceRequest(ch, WifiP2pDnsSdServiceRequest.newInstance(), null)
        m.discoverServices(ch, null)
        main.postDelayed({ rotate() }, planner.nextChangeIn(now) + 1000)
    }

    private fun connectTo(device: WifiP2pDevice) {
        val m = p2p ?: return; val ch = channel ?: return
        if (busy || !running) return
        busy = true
        val cfg = WifiP2pConfig().apply { deviceAddress = device.deviceAddress; wps.setup = WpsInfo.PBC; groupOwnerIntent = rnd.nextInt(16) }
        m.connect(ch, cfg, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) { busy = false }
        })
    }

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
            val m = p2p ?: return; val ch = channel ?: return
            m.requestConnectionInfo(ch) { info ->
                if (info.groupFormed && running) { busy = true; if (info.isGroupOwner) serve() else connect(info.groupOwnerAddress.hostAddress ?: return@requestConnectionInfo) }
                else if (!info.groupFormed) busy = false
            }
        }
    }

    private fun serve() = thread(isDaemon = true) {
        try { ServerSocket(port).use { ss -> ss.soTimeout = 20_000; run(ss.accept(), initiator = false) } } catch (e: Exception) { } finally { finish() }
    }

    private fun connect(host: String) = thread(isDaemon = true) {
        try { Socket().use { s -> s.connect(InetSocketAddress(host, port), 20_000); run(s, initiator = true) } } catch (e: Exception) { } finally { finish() }
    }

    /** Runs the shared session over the socket until the link has been quiet for a while. */
    private fun run(sock: Socket, initiator: Boolean) {
        sock.soTimeout = 15_000
        val out = sock.getOutputStream(); val inp = sock.getInputStream()
        val session = MeshSession(node, MeshCircle(circleKey), initiator, fragment = false, send = { f -> synchronized(out) { FrameStream.write(out, f) } })
        sessions++
        try {
            session.start()
            val pump = thread(isDaemon = true) { while (!session.closed) { Thread.sleep(500); runCatching { session.offer() } } }
            while (!session.closed) session.onFrame(FrameStream.read(inp))             // a read timeout (quiet link) ends the encounter
            pump.interrupt()
        } finally { session.close(); sessions-- }
    }

    private fun finish() { busy = false; val m = p2p; val ch = channel; if (m != null && ch != null) m.removeGroup(ch, null) }
}
