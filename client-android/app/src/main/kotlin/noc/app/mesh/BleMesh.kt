package noc.app.mesh

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import noc.mesh.*
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID

/**
 * Bluetooth Low Energy transport for the mesh. NOT TESTED ON DEVICES (written against the platform API only).
 *  - advertises ONLY a rotating service UUID (no name, no power level, no manufacturer data) -> see AdvertPlanner
 *  - scans for the neighbouring slots' UUIDs, connects, exchanges MeshMsg frames, disconnects
 *  - every connection gets a throw-away label that is forgotten when the link closes
 * Android itself rotates the random BLE address of an advertiser; the app cannot set or read it.
 */
@SuppressLint("MissingPermission")   // the caller checks BLUETOOTH_* permissions before start()
class BleMesh(private val ctx: Context, private val node: MeshNode, private val circleKey: ByteArray, private val clock: () -> Long = System::currentTimeMillis) {
    private val planner = AdvertPlanner(MeshCircle(circleKey))
    private val rnd = SecureRandom()
    private val main = Handler(Looper.getMainLooper())
    private val mgr = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? get() = mgr.adapter
    @Volatile private var running = false
    @Volatile var neighbours = 0; private set
    private var server: BluetoothGattServer? = null
    private var currentService: UUID? = null
    private var currentChar: BluetoothGattCharacteristic? = null
    private val links = HashMap<String, Link>()          // key: connection handle (address string, only while connected, never stored)

    private fun uuid(b: ByteArray): UUID { val bb = ByteBuffer.wrap(b); return UUID(bb.long, bb.long) }

    fun start() {
        if (running || adapter?.isEnabled != true) return
        running = true
        rotate()
    }

    fun stop() {
        running = false; main.removeCallbacksAndMessages(null)
        runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advCb) }
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCb) }
        links.values.toList().forEach { it.close() }; links.clear()
        runCatching { server?.close() }; server = null; neighbours = 0
    }

    /** Every few minutes: new service UUID, new advertisement, new scan filter. */
    private fun rotate() {
        if (!running) return
        val now = clock()
        runCatching { adapter?.bluetoothLeAdvertiser?.stopAdvertising(advCb) }
        runCatching { adapter?.bluetoothLeScanner?.stopScan(scanCb) }
        server?.let { s -> currentService?.let { id -> s.getService(id)?.let { s.removeService(it) } } }
        if (server == null) server = mgr.openGattServer(ctx, gattCb)
        val svc = uuid(planner.advertise(now).serviceUuid); val chr = uuid(planner.characteristicUuid(now))
        val ch = BluetoothGattCharacteristic(chr, BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE or BluetoothGattCharacteristic.PROPERTY_NOTIFY, BluetoothGattCharacteristic.PERMISSION_WRITE)
        ch.addDescriptor(BluetoothGattDescriptor(CCCD, BluetoothGattDescriptor.PERMISSION_WRITE or BluetoothGattDescriptor.PERMISSION_READ))
        val service = BluetoothGattService(svc, BluetoothGattService.SERVICE_TYPE_PRIMARY).apply { addCharacteristic(ch) }
        currentService = svc; currentChar = ch; server?.addService(service)
        val adv = AdvertiseData.Builder().setIncludeDeviceName(false).setIncludeTxPowerLevel(false).addServiceUuid(ParcelUuid(svc)).build()
        val settings = AdvertiseSettings.Builder().setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED).setConnectable(true).setTimeout(0).build()
        adapter?.bluetoothLeAdvertiser?.startAdvertising(settings, adv, advCb)
        val filters = planner.scanFor(now).map { ScanFilter.Builder().setServiceUuid(ParcelUuid(uuid(it))).build() }
        adapter?.bluetoothLeScanner?.startScan(filters, ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(), scanCb)
        main.postDelayed({ rotate() }, planner.nextChangeIn(now) + 1000)
    }

    private val advCb = object : AdvertiseCallback() {}

    private val scanCb = object : ScanCallback() {
        override fun onScanResult(type: Int, r: ScanResult) {
            val dev = r.device
            if (!running || links.containsKey(dev.address) || links.size >= 4) return
            val link = Link(dev.address, central = true)
            links[dev.address] = link
            link.gatt = dev.connectGatt(ctx, false, link.clientCb, BluetoothDevice.TRANSPORT_LE)
        }
    }

    private val gattCb = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(dev: BluetoothDevice, status: Int, state: Int) {
            if (state == BluetoothProfile.STATE_CONNECTED && running && links.size < 4 && !links.containsKey(dev.address)) {
                links[dev.address] = Link(dev.address, central = false).also { it.peer = dev; it.begin() }
            } else if (state == BluetoothProfile.STATE_DISCONNECTED) links.remove(dev.address)?.close()
        }
        override fun onCharacteristicWriteRequest(dev: BluetoothDevice, id: Int, ch: BluetoothGattCharacteristic, prep: Boolean, resp: Boolean, off: Int, value: ByteArray) {
            links[dev.address]?.onFrame(value)
        }
        override fun onDescriptorWriteRequest(dev: BluetoothDevice, id: Int, d: BluetoothGattDescriptor, prep: Boolean, resp: Boolean, off: Int, value: ByteArray) {
            if (resp) server?.sendResponse(dev, id, BluetoothGatt.GATT_SUCCESS, 0, null)
        }
        override fun onNotificationSent(dev: BluetoothDevice, status: Int) { links[dev.address]?.sent() }
    }

    /** One Bluetooth connection. All protocol logic is the shared, tested [MeshSession]; this class only moves frames through GATT. */
    private inner class Link(private val handle: String, val central: Boolean) {
        var gatt: BluetoothGatt? = null
        var peer: BluetoothDevice? = null
        private var writeChar: BluetoothGattCharacteristic? = null
        private val out = ArrayDeque<ByteArray>(); private var busy = false
        private var lastActivity = clock()
        private var session: MeshSession? = null

        val clientCb = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, state: Int) {
                if (state == BluetoothProfile.STATE_CONNECTED) g.requestMtu(247) else if (state == BluetoothProfile.STATE_DISCONNECTED) { links.remove(handle)?.close() }
            }
            override fun onMtuChanged(g: BluetoothGatt, m: Int, status: Int) { g.discoverServices() }
            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                val chr = g.services.firstNotNullOfOrNull { s -> s.characteristics.firstOrNull { it.properties and BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE != 0 } } ?: return g.disconnect()
                g.setCharacteristicNotification(chr, true)
                chr.getDescriptor(CCCD)?.let { it.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE; g.writeDescriptor(it) }
                writeChar = chr
            }
            override fun onDescriptorWrite(g: BluetoothGatt, d: BluetoothGattDescriptor, status: Int) { begin() }
            override fun onCharacteristicChanged(g: BluetoothGatt, c: BluetoothGattCharacteristic) { onFrame(c.value) }
            override fun onCharacteristicWrite(g: BluetoothGatt, c: BluetoothGattCharacteristic, status: Int) { sent() }
        }

        fun begin() {
            if (session != null) return
            session = MeshSession(node, MeshCircle(circleKey), initiator = central, fragment = true, send = { f -> queue(f) }, onClosed = { main.post { close() } })
            neighbours = links.size; session!!.start(); watchdog()
        }

        private fun queue(f: ByteArray) { out.add(f); pump() }

        private fun pump() {
            if (busy) return; val f = out.removeFirstOrNull() ?: return
            busy = true; lastActivity = clock()
            if (central) { writeChar?.let { it.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE; it.value = f; gatt?.writeCharacteristic(it) } }
            else currentChar?.let { it.value = f; peer?.let { p -> server?.notifyCharacteristicChanged(p, it, false) } }
        }

        fun sent() { busy = false; pump() }
        fun onFrame(f: ByteArray) { lastActivity = clock(); session?.onFrame(f) }

        /** Close after a quiet period: an encounter is short. */
        private fun watchdog() {
            main.postDelayed({ if (links.containsKey(handle)) { if (clock() - lastActivity > 8_000 && out.isEmpty()) close() else { session?.offer(); watchdog() } } }, 3_000)
        }

        fun close() {
            session?.close(); links.remove(handle)
            runCatching { gatt?.close() }; runCatching { peer?.let { server?.cancelConnection(it) } }
            neighbours = links.size
        }
    }

    companion object { val CCCD: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb") }
}
