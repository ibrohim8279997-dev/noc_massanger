package noc.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secrets are wrapped by AES-GCM keys that never leave Android Keystore.
 * Both wrapping keys demand a fresh device-credential/biometric authentication (10 s window),
 * so malware cannot read them without the user passing BiometricPrompt.
 */
class KeyVault(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("vault", Context.MODE_PRIVATE)
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun key(alias: String): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(10, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    fun has(slot: String) = prefs.contains(slot)

    fun store(slot: String, alias: String, secret: ByteArray) {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key(alias)) }
        val blob = c.iv + c.doFinal(secret)
        prefs.edit().putString(slot, Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    /** Only works within 10 s after a successful authentication. */
    fun load(slot: String, alias: String): ByteArray? {
        val blob = prefs.getString(slot, null)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return null
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(alias), GCMParameterSpec(128, blob, 0, 12))
        }
        return c.doFinal(blob, 12, blob.size - 12)
    }

    fun forget(slot: String) { prefs.edit().remove(slot).apply() }

    // small non-secret pointers (e.g. which generation of the administrator keys is current)
    fun meta(name: String): String? = prefs.getString("meta_$name", null)
    fun setMeta(name: String, value: String?) { prefs.edit().apply { if (value == null) remove("meta_$name") else putString("meta_$name", value) }.apply() }

    // plain, non-secret integrity pin
    fun pinValue(name: String, value: String): Boolean {
        val old = prefs.getString("pin_$name", null)
        if (old == null) { prefs.edit().putString("pin_$name", value).apply(); return true }
        return old == value
    }
}
