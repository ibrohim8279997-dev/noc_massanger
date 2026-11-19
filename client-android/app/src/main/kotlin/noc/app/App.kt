package noc.app

import android.app.Application
import noc.client.Messenger
import noc.app.data.Db
import noc.client.ServerApi
import noc.app.security.KeyVault
import java.security.SecureRandom

class App : Application() {
    lateinit var vault: KeyVault
    var db: Db? = null
    var messenger: Messenger? = null

    override fun onCreate() {
        super.onCreate(); vault = KeyVault(this)
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(when (getSharedPreferences("ui", MODE_PRIVATE).getString("theme", "system")) {
            "light" -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO
            "dark" -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES
            else -> androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM })
    }

    val unlocked get() = db != null

    /** Call within 10 s after a successful BiometricPrompt: the Keystore key only works in that window. */
    fun unlock() {
        var master = vault.load("master", "noc_master")
        if (master == null) { master = ByteArray(32).also { SecureRandom().nextBytes(it) }; vault.store("master", "noc_master", master) }
        db = Db.open(this, master); master.fill(0)
        connect()
    }

    fun connect() {
        val d = db ?: return
        val url = d.setting("server", "")
        messenger = if (url.isNotBlank()) Messenger(d, ServerApi(url)) else null
    }

    fun lock() { messenger = null; db?.close(); db = null }
}
