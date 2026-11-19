package noc.mesh

import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Where relayed envelopes wait. Always ciphertext; the key lives only in memory (or Keystore on the phone). */
interface EnvelopeStore {
    fun put(id: ByteArray, data: ByteArray)
    fun get(id: ByteArray): ByteArray?
    fun delete(id: ByteArray)
    fun count(): Int
    fun wipe()
}

private val rnd = SecureRandom()
private fun seal(key: ByteArray, data: ByteArray): ByteArray {
    val nonce = ByteArray(12).also { rnd.nextBytes(it) }
    return nonce + Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); doFinal(data) }
}
private fun open(key: ByteArray, blob: ByteArray): ByteArray? = try {
    Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, 12)); doFinal(blob, 12, blob.size - 12) }
} catch (e: Exception) { null }
private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

class EncryptedMemoryStore(private val key: ByteArray) : EnvelopeStore {
    private val m = HashMap<String, ByteArray>()
    override fun put(id: ByteArray, data: ByteArray) { m[hex(id)] = seal(key, data) }
    override fun get(id: ByteArray) = m[hex(id)]?.let { open(key, it) }
    override fun delete(id: ByteArray) { m.remove(hex(id))?.fill(0) }
    override fun count() = m.size
    override fun wipe() { m.values.forEach { it.fill(0) }; m.clear() }
}

/**
 * Same thing on disk. File names are random (not the message id), content is AES-GCM ciphertext, deletion overwrites
 * with zeros first. Files left over from a previous run are destroyed at start: the key died with that process anyway.
 */
class EncryptedFileStore(private val dir: File, private val key: ByteArray) : EnvelopeStore {
    private val files = HashMap<String, File>()
    init { dir.mkdirs(); dir.listFiles()?.forEach { shred(it) } }

    private fun shred(f: File) { try { java.io.RandomAccessFile(f, "rw").use { r -> val z = ByteArray(f.length().toInt()); r.seek(0); r.write(z); r.fd.sync() } } catch (e: Exception) { }; f.delete() }

    override fun put(id: ByteArray, data: ByteArray) {
        delete(id)
        val f = File(dir, hex(ByteArray(12).also { rnd.nextBytes(it) }) + ".bin")
        f.writeBytes(seal(key, data)); files[hex(id)] = f
    }
    override fun get(id: ByteArray) = files[hex(id)]?.let { open(key, it.readBytes()) }
    override fun delete(id: ByteArray) { files.remove(hex(id))?.let { shred(it) } }
    override fun count() = files.size
    override fun wipe() { files.values.forEach { shred(it) }; files.clear() }
}
