package noc.client

import noc.crypto.DeviceAuth
import noc.crypto.RequestSigner
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.security.SecureRandom

class ApiException(val code: Int) : IOException("HTTP $code")

class Packet(val id: String, val data: ByteArray)

/** Talks to the server described in protocol/server-api-v1.md. Never logs. */
class ServerApi(private val base: String) {
    private val http = OkHttpClient.Builder().connectTimeout(java.time.Duration.ofSeconds(20)).readTimeout(java.time.Duration.ofSeconds(40)).build()
    private val rnd = SecureRandom()
    private val enc = java.util.Base64.getUrlEncoder().withoutPadding()
    private val dec = java.util.Base64.getUrlDecoder()
    private fun b64(b: ByteArray) = enc.encodeToString(b)
    private fun unb64(s: String) = dec.decode(s)

    private fun call(signer: RequestSigner?, method: String, path: String, body: ByteArray = ByteArray(0), json: Boolean = false,
                     extra: Map<String, String> = emptyMap()): ByteArray {
        val rb = if (method == "GET" || method == "DELETE") null else body.toRequestBody((if (json) "application/json" else "application/octet-stream").toMediaType())
        val b = Request.Builder().url(base.trimEnd('/') + path).method(method, rb)
        signer?.let { s -> DeviceAuth.headers(s, method, path, body, System.currentTimeMillis() / 1000, ByteArray(16).also { rnd.nextBytes(it) }).forEach { (k, v) -> b.header(k, v) } }
        extra.forEach { (k, v) -> b.header(k, v) }
        http.newCall(b.build()).execute().use { r ->
            if (!r.isSuccessful) throw ApiException(r.code)
            return r.body?.bytes() ?: ByteArray(0)
        }
    }
    private fun j(vararg p: Pair<String, Any?>) = JSONObject(p.toMap()).toString().toByteArray()

    fun bindSuperadmin(token: String, pub: ByteArray) { call(null, "POST", "/v1/admin/bind", j("token" to token, "pubkey" to b64(pub)), json = true) }
    fun addUser(admin: RequestSigner, pub: ByteArray) { call(admin, "PUT", "/v1/admin/users/${b64(pub)}", j("role" to "user"), json = true) }
    fun removeUser(admin: RequestSigner, pub: ByteArray) { call(admin, "DELETE", "/v1/admin/users/${b64(pub)}") }
    fun listUsers(admin: RequestSigner): List<Pair<ByteArray, String>> {
        val a = JSONArray(String(call(admin, "GET", "/v1/admin/users")))
        return (0 until a.length()).map { unb64(a.getJSONObject(it).getString("pubkey")) to a.getJSONObject(it).getString("role") }
    }

    fun putPrekeys(me: RequestSigner, bundle: ByteArray, oneTime: List<ByteArray>) {
        call(me, "PUT", "/v1/prekeys", j("bundle" to b64(bundle), "one_time" to JSONArray(oneTime.map { b64(it) })), json = true)
    }
    /** (long-term bundle, one-time key or null) */
    fun takePrekeys(me: RequestSigner, owner: ByteArray): Pair<ByteArray, ByteArray?> {
        val o = JSONObject(String(call(me, "GET", "/v1/prekeys/${b64(owner)}")))
        return unb64(o.getString("bundle")) to (if (o.isNull("one_time")) null else unb64(o.getString("one_time")))
    }

    fun createMailbox(me: RequestSigner, id: ByteArray, token: ByteArray) { call(me, "POST", "/v1/mailboxes", j("id" to b64(id), "token" to b64(token)), json = true) }
    fun putPacket(me: RequestSigner, mailbox: ByteArray, envelope: ByteArray) { call(me, "POST", "/v1/mailboxes/${b64(mailbox)}/packets", envelope) }
    fun fetch(mailbox: ByteArray, token: ByteArray): List<Packet> {
        val a = JSONArray(String(call(null, "GET", "/v1/mailboxes/${b64(mailbox)}/packets", extra = mapOf("x-mailbox-token" to b64(token)))))
        return (0 until a.length()).map { Packet(a.getJSONObject(it).getString("id"), unb64(a.getJSONObject(it).getString("data"))) }
    }
    fun ack(mailbox: ByteArray, token: ByteArray, packetId: String) {
        call(null, "DELETE", "/v1/mailboxes/${b64(mailbox)}/packets/$packetId", extra = mapOf("x-mailbox-token" to b64(token)))
    }

    /** Wake-up channel: the server only says "new"; content is always fetched over HTTP. */
    fun listen(mailbox: ByteArray, token: ByteArray, onNew: () -> Unit): WebSocket {
        val url = base.trimEnd('/').replaceFirst("http", "ws") + "/v1/ws"
        return http.newWebSocket(Request.Builder().url(url).build(), object : WebSocketListener() {
            override fun onOpen(ws: WebSocket, r: Response) { ws.send(JSONObject(mapOf("mailbox" to b64(mailbox), "token" to b64(token))).toString()) }
            override fun onMessage(ws: WebSocket, text: String) { if (text == "new") onNew() }
        })
    }
}
