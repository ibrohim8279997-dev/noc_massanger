package noc.crypto

import java.io.*
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A file (or a voice message, same thing) is split into chunks; each chunk is AES-256-GCM encrypted
 * under a random per-file key. The key travels only inside the E2E-encrypted manifest.
 * Every chunk has a SHA-256 over its ciphertext; the whole file has a SHA-256 over its plaintext.
 */
class FileManifest(
    val fileId: ByteArray, val key: ByteArray, val size: Long, val count: Int,
    val chunkHashes: List<ByteArray>, val fileHash: ByteArray, val voice: Boolean, val name: String,
) {
    fun serialize(): ByteArray = ByteArrayOutputStream().also { bo ->
        DataOutputStream(bo).run {
            blob(fileId); blob(key); writeLong(size); writeInt(count); writeBoolean(voice)
            blob(fileHash); blob(name.toByteArray()); chunkHashes.forEach { blob(it) }
        }
    }.toByteArray()

    companion object {
        fun parse(raw: ByteArray): FileManifest = try {
            DataInputStream(ByteArrayInputStream(raw)).run {
                val id = blob(); val key = blob(); val size = readLong(); val count = readInt(); val voice = readBoolean()
                val fh = blob(); val name = String(blob())
                if (id.size != 16 || key.size != 32 || fh.size != 32 || count < 0 || count > 1_000_000 || size < 0) throw IOException()
                FileManifest(id, key, size, count, List(count) { blob().also { h -> if (h.size != 32) throw IOException() } }, fh, voice, name)
            }
        } catch (e: IOException) { throw MalformedException("manifest") }
    }
}

object FileCrypto {
    const val CHUNK_SIZE = 11_000   // plaintext bytes per chunk; keeps an envelope under 16 KiB even for prekey messages
    private val rnd = SecureRandom()

    private fun sha(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    private fun aad(id: ByteArray, index: Int, count: Int, size: Long) =
        ByteBuffer.allocate(16 + 4 + 4 + 8).put(id).putInt(index).putInt(count).putLong(size).array()

    private fun cipher(mode: Int, key: ByteArray, index: Int, aad: ByteArray): Cipher {
        val nonce = ByteBuffer.allocate(12).putInt(0).putLong(index.toLong()).array()  // key is unique per file
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce)); updateAAD(aad)
        }
    }

    fun encrypt(data: ByteArray, name: String = "", voice: Boolean = false): Pair<FileManifest, List<ByteArray>> {
        val id = ByteArray(16).also { rnd.nextBytes(it) }
        val key = ByteArray(32).also { rnd.nextBytes(it) }
        val count = maxOf(1, (data.size + CHUNK_SIZE - 1) / CHUNK_SIZE)
        val chunks = (0 until count).map { i ->
            val part = data.copyOfRange(minOf(i * CHUNK_SIZE, data.size), minOf((i + 1) * CHUNK_SIZE, data.size))
            cipher(Cipher.ENCRYPT_MODE, key, i, aad(id, i, count, data.size.toLong())).doFinal(part)
        }
        return FileManifest(id, key, data.size.toLong(), count, chunks.map(::sha), sha(data), voice, name) to chunks
    }
}

/** Collects chunks in any order, verifies each, reports what is missing, verifies the whole file. */
class FileAssembler(private val m: FileManifest) {
    private val parts = arrayOfNulls<ByteArray>(m.count)

    fun missing(): List<Int> = parts.indices.filter { parts[it] == null }

    /** Returns false (and stores nothing) if the chunk is wrong. */
    fun accept(index: Int, ciphertext: ByteArray): Boolean {
        if (index !in 0 until m.count) return false
        if (!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(ciphertext), m.chunkHashes[index])) return false
        parts[index] = try {
            val nonce = ByteBuffer.allocate(12).putInt(0).putLong(index.toLong()).array()
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(m.key, "AES"), GCMParameterSpec(128, nonce))
                updateAAD(ByteBuffer.allocate(16 + 4 + 4 + 8).put(m.fileId).putInt(index).putInt(m.count).putLong(m.size).array())
                doFinal(ciphertext)
            }
        } catch (e: Exception) { return false }
        return true
    }

    fun finish(): ByteArray {
        if (missing().isNotEmpty()) throw MalformedException("missing chunks")
        val out = ByteArrayOutputStream().also { o -> parts.forEach { o.write(it!!) } }.toByteArray()
        if (out.size.toLong() != m.size || !MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(out), m.fileHash))
            throw MalformedException("file checksum")
        return out
    }
}
