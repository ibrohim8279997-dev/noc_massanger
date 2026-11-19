package noc.mesh

/**
 * What a phone puts into its Bluetooth advertisement. No device name, no power level, no manufacturer data, no fixed
 * identifier: only a 128-bit service UUID that is derived from the circle secret and changes every few minutes.
 * Circle members compute the same UUID and find each other; outsiders see a random number that never repeats.
 */
class AdvertSpec(val serviceUuid: ByteArray, val includeName: Boolean = false, val includeTxPower: Boolean = false, val manufacturerData: ByteArray? = null)

class AdvertPlanner(private val circle: MeshCircle, private val slotMs: Long = 5 * 60_000) {
    private fun slot(now: Long) = now / slotMs
    fun advertise(now: Long) = AdvertSpec(circle.adSlotUuid(slot(now)))
    /** Scan for the neighbouring slots too, so small clock differences between phones do not matter. */
    fun scanFor(now: Long): List<ByteArray> = (-1L..1L).map { circle.adSlotUuid(slot(now) + it) }
    /** The characteristic inside the service rotates too: an outsider who connects still learns no fixed identifier. */
    fun characteristicUuid(now: Long): ByteArray = circle.adSlotUuid(slot(now) xor 0x5A5A5A5A5AL)
    fun nextChangeIn(now: Long) = slotMs - now % slotMs
}
