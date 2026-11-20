package noc.app.mesh

import android.content.Context
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.*
import noc.mesh.*
import java.security.SecureRandom

/**
 * Nearby Connections (Google Play services) as a fast link. NOT TESTED ON DEVICES.
 * TRUST: the radio handling is Google's closed-source code in Play services, outside this app's control. The messages
 * are still end-to-end encrypted and every link must first prove membership of the circle ([MeshSession]).
 * Service id and endpoint name are the rotating circle-derived identifier and a random string: not the device name.
 * Needs Google Play services; where they are missing [available] is false and nothing starts. Off unless the user turns it on.
 */
class NearbyMesh(private val ctx: Context, private val node: MeshNode, private val circleKey: ByteArray, private val clock: () -> Long = System::currentTimeMillis) {
    private val planner = AdvertPlanner(MeshCircle(circleKey))
    private val client by lazy { Nearby.getConnectionsClient(ctx) }
    private val rnd = SecureRandom()
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    @Volatile private var running = false
    @Volatile var sessions = 0; private set
    private val links = HashMap<String, MeshSession>()          // endpoint id -> session, only while connected
    private val iRequested = HashSet<String>()                  // endpoints we connected to (we are the initiator there)
    private var scanIdx = 0

    fun available(): Boolean = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(ctx) == ConnectionResult.SUCCESS

    private fun serviceId(uuid: ByteArray) = uuid.joinToString("") { "%02x".format(it) }

    fun start() { if (running || !available()) return; running = true; rotate() }

    fun stop() {
        running = false; handler.removeCallbacksAndMessages(null)
        runCatching { client.stopAdvertising(); client.stopDiscovery(); client.stopAllEndpoints() }
        links.values.toList().forEach { it.close() }; links.clear(); iRequested.clear()
    }

    private fun rotate() {
        if (!running) return
        val now = clock()
        runCatching { client.stopAdvertising(); client.stopDiscovery() }
        val name = ByteArray(6).also { rnd.nextBytes(it) }.joinToString("") { "%02x".format(it) }       // random, not the device name
        client.startAdvertising(name, serviceId(planner.advertise(now).serviceUuid), lifecycle,
            AdvertisingOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
        // discovery looks at one slot at a time (previous, current, next) and cycles, to tolerate clock differences
        val ids = planner.scanFor(now); scanIdx = (scanIdx + 1) % ids.size
        client.startDiscovery(serviceId(ids[scanIdx]), discovery, DiscoveryOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build())
        handler.postDelayed({ rotate() }, 20_000)
    }

    private val discovery = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(id: String, info: DiscoveredEndpointInfo) {
            if (!running || links.size >= 4 || iRequested.contains(id)) return
            iRequested.add(id)
            client.requestConnection("n", id, lifecycle)
        }
        override fun onEndpointLost(id: String) { iRequested.remove(id) }
    }

    private val lifecycle = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(id: String, info: ConnectionInfo) { client.acceptConnection(id, payloads) }   // membership is proven by the session, not by this callback
        override fun onConnectionResult(id: String, result: ConnectionResolution) {
            if (!result.status.isSuccess || !running) { iRequested.remove(id); return }
            val s = MeshSession(node, MeshCircle(circleKey), initiator = iRequested.contains(id), fragment = false,
                send = { f -> client.sendPayload(id, Payload.fromBytes(f)) }, onClosed = { client.disconnectFromEndpoint(id) })
            links[id] = s; sessions = links.size; s.start()
            handler.postDelayed(object : Runnable { override fun run() { val l = links[id] ?: return; if (l.closed) return; l.offer(); handler.postDelayed(this, 1000) } }, 1000)
            handler.postDelayed({ links[id]?.close() }, 120_000)                                    // an encounter is bounded in time
        }
        override fun onDisconnected(id: String) { links.remove(id)?.close(); iRequested.remove(id); sessions = links.size }
    }

    private val payloads = object : PayloadCallback() {
        override fun onPayloadReceived(id: String, p: Payload) { p.asBytes()?.let { links[id]?.onFrame(it) } }
        override fun onPayloadTransferUpdate(id: String, u: PayloadTransferUpdate) {}
    }
}
