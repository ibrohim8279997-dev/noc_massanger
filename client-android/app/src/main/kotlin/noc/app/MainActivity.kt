package noc.app

import android.media.MediaPlayer
import android.media.MediaRecorder
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import noc.app.data.Contact
import noc.app.net.ApiException
import noc.app.security.Integrity
import noc.app.ui.*
import noc.crypto.SeedSigner
import java.io.File

class MainActivity : AppCompatActivity() {
    val app get() = application as App
    val ui = UiState()
    private val handler = Handler(Looper.getMainLooper())
    private val lockRunnable = Runnable { lockNow() }
    private var loop: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        // no screenshots, no screen recording, blank thumbnail in recent apps
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        Integrity.problem(this, app.vault)?.let { ui.screen = Screen.Problem(it) }
        if (ui.screen is Screen.Lock && app.unlocked) ui.screen = Screen.Chats
        setContent { NocTheme { Root() } }
    }

    @androidx.compose.runtime.Composable private fun Root() {
        val s = ui.screen
        BackHandler(enabled = s !is Screen.Lock && s !is Screen.Chats && s !is Screen.Problem && s !is Screen.Setup) {
            ui.screen = when (s) { is Screen.Safety -> Screen.Chat(s.id); is Screen.Admin, is Screen.Meet -> Screen.Contacts; else -> Screen.Chats }
        }
        when (s) {
            Screen.Lock -> LockScreen(this); is Screen.Problem -> ProblemScreen(s.key); Screen.Setup -> SetupScreen(this)
            Screen.Chats -> ChatsScreen(this); Screen.Contacts -> ContactsScreen(this); Screen.Protect -> ProtectScreen(this)
            is Screen.Chat -> ChatScreen(this, s.id); Screen.Settings -> SettingsScreen(this)
            Screen.Meet -> MeetScreen(this); Screen.Admin -> AdminScreen(this); is Screen.Safety -> SafetyScreen(this, s.id)
        }
    }

    // ------------------------------------------------------------------ auto-lock
    override fun onStart() { super.onStart(); handler.removeCallbacks(lockRunnable) }
    override fun onStop() {
        super.onStop()
        if (app.unlocked) handler.postDelayed(lockRunnable, uiPref("lock_s", "30").toLong() * 1000)
    }
    private fun lockNow() { loop?.cancel(); retry?.cancel(); app.lock(); ui.error = null; ui.screen = Screen.Lock }

    // ------------------------------------------------------------------ auth
    fun authenticate(onOk: () -> Unit) {
        val kinds = BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(kinds) != BiometricManager.BIOMETRIC_SUCCESS) { ui.error = getString(R.string.no_lock); return }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) { try { ui.error = null; onOk() } catch (e: Throwable) { ui.error = describe(e) } }
            override fun onAuthenticationError(code: Int, msg: CharSequence) { ui.error = msg.toString() }
        })
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(getString(R.string.unlock_title))
            .setAllowedAuthenticators(kinds).build())
    }

    fun unlockWithAuth() = authenticate {
        app.unlock()
        if (app.messenger == null) ui.screen = Screen.Setup else { ui.screen = Screen.Chats; startLoop() }
    }

    fun withAdmin(block: (SeedSigner) -> Unit) = authenticate {
        val seed = app.vault.load("admin", "noc_admin") ?: error("no admin key")
        val signer = SeedSigner(seed); seed.fill(0)
        io { block(signer) }
    }

    // ------------------------------------------------------------------ helpers
    // On-screen only, never logged. Message is clipped; bound values are never part of SQLite/libsignal messages.
    private fun describe(e: Throwable): String = when {
        e is ApiException && e.code == 401 -> getString(R.string.err_401)
        e is ApiException && e.code == 404 -> getString(R.string.err_404)
        e is ApiException -> getString(R.string.error_generic, "HTTP ${e.code}")
        else -> getString(R.string.error_generic, e.javaClass.simpleName + (e.message?.let { ": " + it.take(120) } ?: ""))
    }

    fun io(block: suspend () -> Unit) { lifecycleScope.launch(Dispatchers.IO) { try { block() } catch (e: Throwable) { ui.error = describe(e) } } }

    fun uiPref(k: String, def: String) = getSharedPreferences("ui", MODE_PRIVATE).getString(k, def) ?: def
    fun setUiPref(k: String, v: String) { getSharedPreferences("ui", MODE_PRIVATE).edit().putString(k, v).apply() }
    fun setTheme(v: String) {
        setUiPref("theme", v)
        AppCompatDelegate.setDefaultNightMode(when (v) { "light" -> AppCompatDelegate.MODE_NIGHT_NO; "dark" -> AppCompatDelegate.MODE_NIGHT_YES; else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM })
    }
    fun setLanguage(v: String) {
        setUiPref("lang", v)
        AppCompatDelegate.setApplicationLocales(if (v == "system") LocaleListCompat.getEmptyLocaleList() else LocaleListCompat.forLanguageTags(v))
    }

    // ------------------------------------------------------------------ server connection
    private var retry: Job? = null

    fun connectServer(url: String, token: String, onCard: (String) -> Unit) {
        fun proceed(adminSeed: ByteArray?) = io {
            val db = app.db!!; db.setSetting("server", url); app.connect()
            val m = app.messenger!!
            try {
                if (adminSeed != null) {
                    val s = SeedSigner(adminSeed)
                    m.api.bindSuperadmin(token, s.publicKey); m.api.addUser(s, m.signer.publicKey)
                }
                m.sync(); ui.error = null; ui.registered = true; ui.screen = Screen.Chats; startLoop()
            } catch (e: ApiException) {
                if (adminSeed != null) app.vault.forget("admin")
                if (e.code == 401 && adminSeed == null) {
                    // not registered yet: show the card for the administrator and keep trying by itself
                    ui.error = null; onCard(m.deviceCard()); waitForAdmin(m)
                } else throw e
            }
        }
        if (token.isBlank()) proceed(null) else authenticate {
            val seed = SeedSigner.newSeed(); app.vault.store("admin", "noc_admin", seed)   // needs the fresh authentication
            proceed(seed)
        }
    }

    private fun waitForAdmin(m: noc.app.core.Messenger) {
        retry?.cancel()
        retry = lifecycleScope.launch(Dispatchers.IO) {
            while (isActive && app.unlocked) {
                delay(3000)
                try { m.sync(); ui.registered = true; ui.screen = Screen.Chats; startLoop(); break }
                catch (e: CancellationException) { throw e }
                catch (e: ApiException) { if (e.code != 401) { ui.error = describe(e); break } }
                catch (e: Exception) { }
            }
        }
    }

    /** Every cycle: make sure this device is registered (mailbox + prekeys), then fetch. Survives app restarts. */
    private fun startLoop() {
        loop?.cancel(); retry?.cancel()
        val m = app.messenger ?: return
        loop = lifecycleScope.launch(Dispatchers.IO) {
            val wake = Channel<Unit>(Channel.CONFLATED)
            var ws: okhttp3.WebSocket? = null
            try {
                while (isActive) {
                    try {
                        m.sync(); ui.registered = true
                        if (ws == null) ws = runCatching { m.listen { wake.trySend(Unit) } }.getOrNull()
                        val n = m.poll(); val p = m.purgeExpired(); if (n > 0 || p > 0) ui.tick++
                    } catch (e: CancellationException) { throw e }
                    catch (e: ApiException) { if (e.code == 401) ui.registered = false }
                    catch (e: Exception) { }
                    withTimeoutOrNull(15_000) { wake.receive() }
                }
            } finally { ws?.close(1000, null) }
        }
    }

    // ------------------------------------------------------------------ chat actions
    fun sendText(c: Contact, text: String) = io { app.messenger!!.sendText(c, text); ui.tick++ }

    fun sendPicked(c: Contact, uri: Uri) = io {
        val limit = 20 * 1024 * 1024
        val data = contentResolver.openInputStream(uri)!!.use { it.readNBytes(limit + 1) }
        if (data.size > limit) { ui.error = getString(R.string.too_large); return@io }
        val name = contentResolver.query(uri, null, null, null, null)?.use { if (it.moveToFirst()) it.getString(it.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)) else null } ?: "file"
        app.messenger!!.sendFile(c, data, name, false); ui.tick++
    }

    fun sendRecording(c: Contact, rec: MediaRecorder, f: File) = io {
        try { rec.stop() } catch (_: RuntimeException) { }
        rec.release()
        val data = f.readBytes(); f.delete()
        if (data.isNotEmpty()) { app.messenger!!.sendFile(c, data, "voice.m4a", true); ui.tick++ }
    }

    fun saveFile(msgId: Long, uri: Uri) = io {
        val data = app.db!!.messageFile(msgId) ?: return@io
        contentResolver.openOutputStream(uri)!!.use { it.write(data) }
    }

    fun playVoice(msgId: Long) = io {
        val data = app.db!!.messageFile(msgId) ?: return@io
        val f = File.createTempFile("play", ".m4a", cacheDir).also { it.writeBytes(data) }
        runOnUiThread {
            MediaPlayer().apply {
                setDataSource(f.path); prepare(); start()
                setOnCompletionListener { release(); f.delete() }
            }
        }
    }

    fun wipe() {
        lockNow()
        deleteDatabase("noc.db"); app.vault.forget("master"); app.vault.forget("admin")
    }
}
