package noc.crypto

import java.security.*
import java.util.Base64

/** Signs server requests exactly as protocol/server-api-v1.md says. On Android the key lives in Keystore. */
interface RequestSigner {
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

class SoftwareSigner(private val priv: PrivateKey, override val publicKey: ByteArray) : RequestSigner {
    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("Ed25519").run { initSign(priv); update(message); sign() }

    companion object {
        fun generate(): SoftwareSigner = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().let {
            SoftwareSigner(it.private, it.public.encoded.takeLast(32).toByteArray())
        }
    }
}

object DeviceAuth {
    private val enc = Base64.getUrlEncoder().withoutPadding()
    fun b64(x: ByteArray): String = enc.encodeToString(x)

    fun message(method: String, path: String, ts: String, nonce: String, body: ByteArray): ByteArray =
        "NOC1\n${method.uppercase()}\n$path\n$ts\n$nonce\n".toByteArray() + java.security.MessageDigest.getInstance("SHA-256").digest(body)

    fun headers(signer: RequestSigner, method: String, path: String, body: ByteArray, nowS: Long, nonce: ByteArray): Map<String, String> {
        val n = b64(nonce); val ts = nowS.toString()
        val msg = message(method, path, ts, n, body)
        val h = mutableMapOf("x-key" to b64(signer.publicKey), "x-ts" to ts, "x-nonce" to n, "x-sig" to b64(signer.sign(msg)))
        if (signer is PqCapable) h["x-pq-sig"] = b64(signer.pqSign("NOC1-PQ\n".toByteArray() + msg))   // the administrator signs with BOTH algorithms
        return h
    }
}

/** Ed25519 from a 32-byte seed (BouncyCastle lightweight API: same result on every Android version). */
class SeedSigner(seed: ByteArray) : RequestSigner {
    private val priv = org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0)
    override val publicKey: ByteArray = priv.generatePublicKey().encoded
    override fun sign(message: ByteArray): ByteArray =
        org.bouncycastle.crypto.signers.Ed25519Signer().run { init(true, priv); update(message, 0, message.size); generateSignature() }

    companion object { fun newSeed(): ByteArray = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) } }
}

object Ed25519Verify {
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        org.bouncycastle.crypto.signers.Ed25519Signer().run {
            init(false, org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(publicKey, 0)); update(message, 0, message.size); verifySignature(signature)
        }
    } catch (e: Exception) { false }
}

interface PqCapable { fun pqSign(message: ByteArray): ByteArray }

/** The administrator: Ed25519 + ML-DSA-65. The server accepts a request only if BOTH signatures verify. */
class HybridSigner(val ed: SeedSigner, val pqPublic: ByteArray, private val pqSecret: ByteArray) : RequestSigner by ed, PqCapable {
    override fun pqSign(message: ByteArray) = MlDsa65.sign(pqSecret, message)
    fun pqSecretCopy(): ByteArray = pqSecret.copyOf()
    companion object {
        fun generate(): HybridSigner { val (pk, sk) = MlDsa65.keyPair(); return HybridSigner(SeedSigner(SeedSigner.newSeed()), pk, sk) }
        fun from(edSeed: ByteArray, pk: ByteArray, sk: ByteArray) = HybridSigner(SeedSigner(edSeed), pk, sk)
    }
}
