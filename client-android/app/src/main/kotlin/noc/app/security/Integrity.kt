package noc.app.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File
import java.security.MessageDigest
import noc.app.BuildConfig

/** Best-effort checks. A determined attacker with root can bypass any of them; they stop casual and automated abuse. */
object Integrity {
    private val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk",
        "/data/local/bin/su", "/data/local/xbin/su", "/system/sd/xbin/su", "/vendor/bin/su")

    /** Returns a problem key (matches a string resource) or null when everything is fine. */
    fun problem(ctx: Context, vault: KeyVault): String? {
        if (!BuildConfig.DEBUG) {
            if (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) return "debuggable"
            if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return "debugger"
            if (Build.TAGS?.contains("test-keys") == true || suPaths.any { File(it).exists() }) return "root"
        }
        val sig = signingDigest(ctx) ?: return "signature"
        if (!vault.pinValue("signer", sig)) return "signature"   // app was re-signed / tampered
        return null
    }

    private fun signingDigest(ctx: Context): String? = try {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners ?: return null
        MessageDigest.getInstance("SHA-256").digest(signers.first().toByteArray()).joinToString("") { "%02x".format(it) }
    } catch (e: Exception) { null }
}
