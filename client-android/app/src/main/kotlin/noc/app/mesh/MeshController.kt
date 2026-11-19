package noc.app.mesh

import android.content.Context
import noc.client.Messenger
import noc.mesh.*
import java.io.File
import java.security.SecureRandom

/**
 * Owns the mesh for one unlocked session. The relay buffer is encrypted with a key that exists only in RAM:
 * locking the app or killing the process makes everything in the buffer unreadable, and leftover files are shredded at next start.
 */
class MeshController(private val ctx: Context, private val messenger: Messenger) {
    private val key = ByteArray(32).also { SecureRandom().nextBytes(it) }     // never written anywhere
    private val store = EncryptedFileStore(File(ctx.cacheDir, "mesh"), key)
    val node = MeshNode(MeshCircle(messenger.circleKey), store, System::currentTimeMillis, { ct -> messenger.receiveCiphertext(ct) })
    private val ble = BleMesh(ctx, node, messenger.circleKey)

    val neighbours get() = ble.neighbours
    val held get() = node.held()

    fun start() { messenger.meshOut = { ct -> node.inject(ct) }; ble.start() }

    fun tick() { node.purge(); messenger.requestMissingChunks() }

    fun stop() { messenger.meshOut = null; ble.stop(); store.wipe(); key.fill(0) }
}
