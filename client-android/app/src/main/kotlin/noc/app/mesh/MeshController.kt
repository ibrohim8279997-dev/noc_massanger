package noc.app.mesh

import android.content.Context
import noc.client.Messenger
import noc.mesh.*
import java.io.File
import java.security.SecureRandom

/**
 * Owns the mesh for one unlocked session. The relay buffer is encrypted with a key that exists only in RAM:
 * locking the app or killing the process makes everything in the buffer unreadable, and leftover files are shredded at next start.
 * Transports: Bluetooth (always, when mesh is on), Wi-Fi Direct and Nearby Connections (only if the user switched them on: fast links for big files).
 */
class MeshController(private val ctx: Context, private val messenger: Messenger, private val wifi: Boolean = false, private val nearby: Boolean = false) {
    private val key = ByteArray(32).also { SecureRandom().nextBytes(it) }     // never written anywhere
    private val store = EncryptedFileStore(File(ctx.cacheDir, "mesh"), key)
    private val fast = wifi || nearby
    // fast links can carry whole files, so the relay buffer is larger when one is enabled
    val node = MeshNode(MeshCircle(messenger.circleKey), store, System::currentTimeMillis, { ct -> messenger.receiveCiphertext(ct) },
        if (fast) Limits(maxEntries = 128, maxBytes = 128L * MESH_ENVELOPE) else Limits())
    private val ble = BleMesh(ctx, node, messenger.circleKey)
    private val wifiDirect = if (wifi) WifiDirectMesh(ctx, node, messenger.circleKey) else null
    private val nearbyLink = if (nearby) NearbyMesh(ctx, node, messenger.circleKey) else null

    val neighbours get() = ble.neighbours + (wifiDirect?.sessions ?: 0) + (nearbyLink?.sessions ?: 0)
    val held get() = node.held()
    val nearbyAvailable get() = nearbyLink?.available() ?: true

    fun start() {
        messenger.meshOut = { ct -> node.inject(ct) }
        messenger.meshFileLimit = if (fast) 20 * 1024 * 1024 else 200 * 1024        // big files only when a fast link exists
        ble.start(); wifiDirect?.start(); nearbyLink?.start()
    }

    fun tick() { node.purge(); messenger.requestMissingChunks() }

    fun stop() { messenger.meshOut = null; ble.stop(); wifiDirect?.stop(); nearbyLink?.stop(); store.wipe(); key.fill(0) }
}
