package noc.crypto

import org.signal.libsignal.protocol.IdentityKey
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator
import java.io.*
import java.security.SecureRandom
import java.util.Base64

/** QR payload exchanged in person: who I am (identity + device key), where to write to me, one-time nonce. */
class Invite(
    val identity: IdentityKey, val deviceKey: ByteArray, val mailboxId: ByteArray,
    val nonce: ByteArray, val replyTo: ByteArray?, val expiresAtS: Long, val circleKey: ByteArray? = null,
) {
    fun encode(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ByteArrayOutputStream().also { bo -> DataOutputStream(bo).run {
            writeByte(2); blob(identity.serialize()); blob(deviceKey); blob(mailboxId); blob(nonce)
            blob(replyTo ?: ByteArray(0)); writeLong(expiresAtS); blob(circleKey ?: ByteArray(0))
        } }.toByteArray())

    companion object {
        fun decode(s: String, nowS: Long): Invite = try {
            DataInputStream(ByteArrayInputStream(Base64.getUrlDecoder().decode(s))).run {
                if (readByte().toInt() != 2) throw IOException()
                val ik = IdentityKey(blob()); val dk = blob(); val mb = blob(); val n = blob(); val r = blob(); val exp = readLong(); val ck = blob()
                if (dk.size != 32 || mb.size != 16 || n.size != 16 || (r.isNotEmpty() && r.size != 16) || (ck.isNotEmpty() && ck.size != 32)) throw IOException()
                if (exp < nowS) throw MalformedException("invite expired")
                Invite(ik, dk, mb, n, r.takeIf { it.isNotEmpty() }, exp, ck.takeIf { it.isNotEmpty() })
            }
        } catch (e: MalformedException) { throw e } catch (e: Exception) { throw MalformedException("invite") }
    }
}

/** Issuer side: invites are valid for a short time and burn when the counter-invite arrives. */
class InviteBook(private val ttlS: Long = 300) {
    private val open = HashMap<String, Long>()
    private val rnd = SecureRandom()

    fun issue(identity: IdentityKey, deviceKey: ByteArray, mailboxId: ByteArray, nowS: Long, replyTo: ByteArray? = null, circleKey: ByteArray? = null): Invite {
        val nonce = ByteArray(16).also { rnd.nextBytes(it) }
        open[Base64.getEncoder().encodeToString(nonce)] = nowS + ttlS
        return Invite(identity, deviceKey, mailboxId, nonce, replyTo, nowS + ttlS, circleKey)
    }

    /** True once per issued invite, only before expiry. */
    fun redeem(nonce: ByteArray, nowS: Long): Boolean {
        val exp = open.remove(Base64.getEncoder().encodeToString(nonce)) ?: return false
        return exp >= nowS
    }
}

object SafetyNumber {
    /** 60 digits both people compare by eye or by scan. Same on both sides. */
    fun of(localId: ByteArray, local: IdentityKey, remoteId: ByteArray, remote: IdentityKey): String =
        NumericFingerprintGenerator(5200).createFor(2, localId, local, remoteId, remote).displayableFingerprint.displayText
}
