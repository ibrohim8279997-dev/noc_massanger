package noc.crypto

/**
 * ML-DSA-65 (FIPS 204) from liboqs, called through a thin JNI bridge (native/nocoqs/oqs_jni.c).
 * On Android the bridge and liboqs are compiled into libnocoqs.so; on a build machine tests load it by path.
 * Nothing in this file implements cryptography.
 */
object MlDsa65 {
    const val PK = 1952
    const val SK = 4032
    const val SIG_MAX = 3309

    private val loaded: Boolean by lazy {
        try { System.loadLibrary("nocoqs") } catch (e: UnsatisfiedLinkError) {
            val p = System.getProperty("noc.oqs.jni") ?: System.getenv("NOC_OQS_JNI") ?: throw e
            System.load(p)
        }
        true
    }

    @JvmStatic private external fun nativeKeypair(): ByteArray?
    @JvmStatic private external fun nativeSign(sk: ByteArray, msg: ByteArray): ByteArray?
    @JvmStatic private external fun nativeVerify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    fun available(): Boolean = try { loaded } catch (e: Throwable) { false }

    /** (public key, secret key) */
    fun keyPair(): Pair<ByteArray, ByteArray> {
        check(loaded)
        val both = nativeKeypair() ?: error("ML-DSA key generation failed")
        check(both.size == PK + SK)
        return both.copyOfRange(0, PK) to both.copyOfRange(PK, PK + SK).also { both.fill(0) }
    }

    fun sign(secretKey: ByteArray, message: ByteArray): ByteArray {
        check(loaded); require(secretKey.size == SK) { "bad ML-DSA secret key" }
        return nativeSign(secretKey, message) ?: error("ML-DSA signing failed")
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != PK || signature.isEmpty() || signature.size > SIG_MAX) return false
        check(loaded); return nativeVerify(publicKey, message, signature)
    }
}
