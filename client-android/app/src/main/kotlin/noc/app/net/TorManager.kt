package noc.app.net

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * Runs the bundled Tor client as a child process and exposes its SOCKS port on localhost.
 * 1) plain Tor; 2) if it does not bootstrap in [timeoutMs], automatic fallback to the bridges the user configured
 * (obfs4 or Snowflake lines, pasted in Settings). No bridges configured: reports FAILED and nothing leaves the phone.
 */
class TorManager(private val ctx: Context) {
    enum class State { STOPPED, STARTING, READY, STARTING_BRIDGES, FAILED }

    val socksPort = 19050
    val state = AtomicReference(State.STOPPED)
    @Volatile var progress = 0
    private var proc: Process? = null
    private val lib get() = File(ctx.applicationInfo.nativeLibraryDir)

    @Synchronized fun stop() { proc?.destroy(); proc = null; state.set(State.STOPPED); progress = 0 }

    /** Blocks until READY or FAILED. Call from a background thread. */
    fun startWithFallback(bridges: List<String>, timeoutMs: Long = 90_000): Boolean {
        if (state.get() == State.READY) return true
        if (launch(emptyList(), State.STARTING, timeoutMs)) return true
        if (bridges.isEmpty()) { stop(); state.set(State.FAILED); return false }
        stop()
        if (launch(bridges, State.STARTING_BRIDGES, timeoutMs)) return true
        stop(); state.set(State.FAILED); return false
    }

    @Synchronized private fun launch(bridges: List<String>, st: State, timeoutMs: Long): Boolean {
        stop(); state.set(st)
        val dir = File(ctx.filesDir, "tor").also { it.mkdirs() }
        val data = File(dir, "data").also { it.mkdirs() }
        val rc = File(dir, "torrc")
        val cfg = StringBuilder()
            .appendLine("DataDirectory ${data.path}").appendLine("SocksPort 127.0.0.1:$socksPort")
            .appendLine("ClientOnly 1").appendLine("SafeSocks 1").appendLine("AvoidDiskWrites 1")
            .appendLine("ControlPort 0").appendLine("Log notice stdout")
        if (bridges.isNotEmpty()) {
            cfg.appendLine("UseBridges 1")
            File(lib, "libobfs4proxy.so").takeIf { it.exists() }?.let { cfg.appendLine("ClientTransportPlugin obfs4 exec ${it.path}") }
            File(lib, "libsnowflake.so").takeIf { it.exists() }?.let { cfg.appendLine("ClientTransportPlugin snowflake exec ${it.path}") }
            bridges.forEach { cfg.appendLine("Bridge $it") }
        }
        rc.writeText(cfg.toString())
        val p = ProcessBuilder(File(lib, "libtor.so").path, "-f", rc.path).redirectErrorStream(true).start()
        proc = p
        val ready = java.util.concurrent.CountDownLatch(1)
        Thread {
            p.inputStream.bufferedReader().forEachLine { line ->
                Regex("Bootstrapped (\\d+)%").find(line)?.let { m -> progress = m.groupValues[1].toInt(); if (progress >= 100) ready.countDown() }
            }
        }.apply { isDaemon = true }.start()
        val ok = ready.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
        if (ok) state.set(State.READY)
        return ok
    }
}
