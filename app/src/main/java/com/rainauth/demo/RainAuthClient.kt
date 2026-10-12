package com.rainauth.demo

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** 授权票据（服务端 Ed25519 签名，支持离线校验） */
data class Ticket(
    val v: Int,
    val app: String,
    val uid: Long,
    val dev: String?,
    val iat: Long,
    val exp: Long?,
    val nonce: String,
    val sig: ByteArray,
)

/** 一次验证的结果 */
data class VerifyResult(
    val ok: Boolean,
    val msg: String,
    val userId: Long?,
    val expireAt: String?,
    val deviceUsed: Int?,
    val deviceMax: Int?,
    val activatedNow: Boolean,
    val ticket: Ticket?,
    val serverTime: Long?,
)

/**
 * RainAuth 客户端。
 *
 * 生命周期：`handshake()` → 若干次 `verify()`。
 * 每次 verify 消耗一个严格递增的 seq，nonce 由 seq 派生，服务端会强制校验两者一致。
 */
class RainAuthClient(
    private val baseUrl: String,
    private val appKey: String,
    private val appSecret: String,
    /** 固定写入 App 的服务端公钥摘要。公钥不一致直接拒绝会话。 */
    private val pinnedX25519: ByteArray,
    private val pinnedEd25519: ByteArray,
) {
    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        // 证书校验保持默认开启，不接受任何主机名/证书绕过
        .build()

    private val json = "application/json; charset=utf-8".toMediaType()

    private var sid: String = ""
    private var c2s: ByteArray = ByteArray(0)
    private var s2c: ByteArray = ByteArray(0)
    private var seq: Long = 0

    val sessionId: String get() = sid

    /**
     * 握手。三重 DH：
     *   dh1 = X25519(e_c, e_s)          临时×临时，前向保密
     *   dh2 = X25519(e_c, 服务端静态)    确认服务端身份
     *   dh3 = X25519(a_x, e_s)          证明客户端持有 app_secret
     *
     * 服务端会用 Ed25519 签名的 transcript 自证，客户端必须验签通过才继续。
     */
    suspend fun handshake(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val eCPriv = RainCrypto.randomBytes(32)
            val eCPub = RainCrypto.x25519Base(eCPriv)
            val nC = RainCrypto.randomBytes(16)
            val ts = System.currentTimeMillis() / 1000

            val b64Ec = RainCrypto.b64e(eCPub)
            val b64Nc = RainCrypto.b64e(nC)

            val body = JSONObject()
                .put("v", 1)
                .put("app_key", appKey)
                .put("e_c", b64Ec)
                .put("n_c", b64Nc)
                .put("ts", ts)
                .toString()

            val resp = post("$baseUrl/hs", body)
            val d = resp.optJSONObject("data") ?: resp
            val newSid = d.optString("sid")
            val b64Es = d.optString("e_s")
            val b64Ns = d.optString("n_s")
            val b64Sig = d.optString("sig")
            if (newSid.isEmpty() || b64Es.isEmpty() || b64Ns.isEmpty() || b64Sig.isEmpty()) {
                return@withContext Result.failure(Exception("握手响应缺少字段：$resp"))
            }

            // ① 验服务端身份签名 —— 用 pin 住的 Ed25519 公钥
            val transcript = RainCrypto.handshakeTranscript(
                appKey, newSid, b64Ec, b64Nc, b64Es, b64Ns, ts,
            )
            val sigOk = RainCrypto.ed25519Verify(
                pinnedEd25519, transcript, RainCrypto.b64d(b64Sig),
            )
            if (!sigOk) {
                return@withContext Result.failure(Exception("服务端身份签名校验失败，拒绝建立会话"))
            }

            val eSPub = RainCrypto.b64d(b64Es)
            val nS = RainCrypto.b64d(b64Ns)

            // ② 三重 DH
            val dh1 = RainCrypto.x25519(eCPriv, eSPub)
            val dh2 = RainCrypto.x25519(eCPriv, pinnedX25519)
            val axPriv = RainCrypto.clientStaticSecret(appSecret)
            val dh3 = RainCrypto.x25519(axPriv, eSPub)

            // 低阶点攻击检测：X25519 结果为全零说明对端公钥非法
            if (dh1.all { it == 0.toByte() } ||
                dh2.all { it == 0.toByte() } ||
                dh3.all { it == 0.toByte() }
            ) {
                return@withContext Result.failure(Exception("X25519 协商失败（对端公钥非法）"))
            }

            val keys = RainCrypto.deriveSessionKeys(
                appKey, eCPub, eSPub, nC, nS, dh1, dh2, dh3,
            )
            sid = newSid
            c2s = keys.c2s
            s2c = keys.s2c
            seq = 0
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /** 提交一次验证。card 与 uid 二选一；账号模式必须带 userToken。 */
    suspend fun verify(
        card: String? = null,
        uid: Long? = null,
        userToken: String? = null,
        device: String? = null,
        deviceName: String? = null,
    ): Result<VerifyResult> = withContext(Dispatchers.IO) {
        try {
            if (sid.isEmpty()) return@withContext Result.failure(Exception("尚未握手"))

            val next = seq + 1
            val inner = JSONObject().put("action", "verify")
            card?.takeIf { it.isNotBlank() }?.let { inner.put("card", it) }
            uid?.let { inner.put("uid", it) }
            userToken?.takeIf { it.isNotBlank() }?.let { inner.put("user_token", it) }
            device?.takeIf { it.isNotBlank() }?.let {
                inner.put("device", it)
                inner.put("device_name", deviceName ?: "android")
            }
            inner.put("app_ver", BuildConfig.VERSION_NAME)
            inner.put("ts", System.currentTimeMillis() / 1000)

            val nonce = RainCrypto.seqNonce(next)
            val aadIn = RainCrypto.aad(RainCrypto.AAD_C2S, sid, next)
            val ct = RainCrypto.seal(c2s, nonce, aadIn, inner.toString().toByteArray())

            val body = JSONObject()
                .put("sid", sid)
                .put("seq", next)
                .put("n", RainCrypto.b64e(nonce))
                .put("ct", RainCrypto.b64e(ct))
                .toString()

            val raw = post("$baseUrl/verify", body)

            // ⚠️ 服务端把信封包在 data 里：
            //   { "code": 200, "data": { "seq":…, "n":…, "ct":… } }
            // 顶层取 seq/n/ct 会全部落空。（握手同样是这层包装。）
            // 这里同时兼容「已解包」与「未解包」两种形态，避免服务端调整后再次踩坑。
            val resp = raw.optJSONObject("data") ?: raw

            val outSeq = resp.optLong("seq", -1)
            val outN = resp.optString("n")
            val outCt = resp.optString("ct")
            if (outSeq < 0 || outN.isEmpty() || outCt.isEmpty()) {
                // 业务错误（code != 200）时不会有信封，直接把服务端的话带出来
                val code = raw.optInt("code", -1)
                val msg = raw.optString("msg").ifEmpty { "响应结构异常" }
                return@withContext Result.failure(
                    Exception(if (code != -1 && code != 200) "$msg（HTTP 业务码 $code）" else msg)
                )
            }

            val outNonce = RainCrypto.b64d(outN)
            val aadOut = RainCrypto.aad(RainCrypto.AAD_S2C, sid, outSeq)
            val plain = RainCrypto.open(s2c, outNonce, aadOut, RainCrypto.b64d(outCt))
                ?: return@withContext Result.failure(Exception("响应解密失败：会话密钥不匹配或密文被篡改"))

            seq = next

            val reply = JSONObject(String(plain))
            val ok = reply.optBoolean("ok", false)
            val msg = reply.optString("msg")
            val data = reply.optJSONObject("data")

            Result.success(
                VerifyResult(
                    ok = ok,
                    msg = msg,
                    userId = data?.optLong("user_id"),
                    expireAt = data?.optString("expire_at"),
                    deviceUsed = data?.optInt("device_used"),
                    deviceMax = data?.optInt("device_max"),
                    activatedNow = data?.optBoolean("activated_now") ?: false,
                    ticket = data?.optJSONObject("ticket")?.let { parseTicket(it) },
                    serverTime = data?.optLong("server_time"),
                )
            )
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    private fun parseTicket(o: JSONObject): Ticket = Ticket(
        v = o.optInt("v"),
        app = o.optString("app"),
        uid = o.optLong("uid"),
        dev = o.optString("dev").takeIf { it.isNotEmpty() },
        iat = o.optLong("iat"),
        exp = if (o.has("exp") && !o.isNull("exp")) o.optLong("exp") else null,
        nonce = o.optString("nonce"),
        sig = RainCrypto.b64d(o.optString("ticket_sig")),
    )

    private fun post(url: String, body: String): JSONObject {
        val req = Request.Builder()
            .url(url)
            .post(body.toRequestBody(json))
            .header("Content-Type", "application/json")
            .build()
        http.newCall(req).execute().use { r ->
            val text = r.body?.string().orEmpty()
            if (text.isBlank()) throw Exception("HTTP ${r.code}：空响应")
            return JSONObject(text)
        }
    }

    companion object {
        /**
         * 离线验票。
         *
         * 只做密码学校验：签名 + 有效期内。**设备归属、应用归属、签发时间的
         * 合理性校验不在这一步** —— 调用方必须自行核对 `ticket.dev` 与
         * 本机设备标识、`ticket.app` 与当前 app_key，否则一张从别处拷来的
         * 票据同样能通过验签。
         */
        fun verifyTicketOffline(t: Ticket, pinnedEd25519: ByteArray): Pair<Boolean, String> {
            val canonical = RainCrypto.ticketCanonical(t)
            if (!RainCrypto.ed25519Verify(pinnedEd25519, canonical, t.sig)) {
                return false to "授权凭证签名无效"
            }
            if (t.v != 1) return false to "不支持的票据版本：${t.v}"
            t.exp?.let {
                if (it < System.currentTimeMillis() / 1000) return false to "授权凭证已过期"
            }
            // iat 不允许来自未来（容忍 5 分钟时钟偏差）
            if (t.iat > System.currentTimeMillis() / 1000 + 300) {
                return false to "授权凭证签发时间异常"
            }
            return true to "ok"
        }
    }
}
