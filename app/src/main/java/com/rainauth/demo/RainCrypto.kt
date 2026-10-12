package com.rainauth.demo

import android.util.Base64
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.math.ec.rfc7748.X25519
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/**
 * RainAuth 协议 `jjyv2/v1` 的密码学原语。
 *
 * 与服务端 `server/src/crypto.rs` 逐字节对应，任何一处不一致都会导致握手失败。
 * 常量与 `sdk/cpp/include/rainauth.hpp` 的 label 命名空间保持一致。
 */
object RainCrypto {

    // ── 协议常量 ────────────────────────────────────────────
    const val PROTO = "jjyv2/v1"
    const val SALT_LABEL = "jjyv2/v1/salt"
    const val AAD_C2S = "jjyv2/v1/c2s"
    const val AAD_S2C = "jjyv2/v1/s2c"
    const val HS_PREFIX = "jjyv2/v1/handshake"
    const val TICKET_PREFIX = "jjyv2/v1/ticket"
    const val CLIENT_STATIC_INFO = "x25519/client-static"

    private val rng = SecureRandom()

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    // ── 编码：标准 base64 含填充，非 URL-safe ───────────────
    fun b64e(b: ByteArray): String =
        Base64.encodeToString(b, Base64.NO_WRAP)

    fun b64d(s: String): ByteArray =
        Base64.decode(s, Base64.DEFAULT)

    // ── 哈希 ────────────────────────────────────────────────
    fun sha256(vararg parts: ByteArray): ByteArray {
        val d = SHA256Digest()
        for (p in parts) d.update(p, 0, p.size)
        return ByteArray(32).also { d.doFinal(it, 0) }
    }

    // ── HKDF-SHA256 ─────────────────────────────────────────
    fun hkdf(salt: ByteArray, ikm: ByteArray, info: ByteArray, len: Int = 32): ByteArray {
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(ikm, salt, info))
        return ByteArray(len).also { gen.generateBytes(it, 0, len) }
    }

    // ── X25519 ──────────────────────────────────────────────
    fun x25519Base(priv: ByteArray): ByteArray {
        require(priv.size == 32) { "X25519 私钥必须 32 字节" }
        val pub = ByteArray(32)
        X25519.scalarMultBase(priv, 0, pub, 0)
        return pub
    }

    /** 共享密钥。任一侧为低阶点会返回全零 —— 调用方必须检查。 */
    fun x25519(priv: ByteArray, peerPub: ByteArray): ByteArray {
        require(priv.size == 32 && peerPub.size == 32) { "X25519 参数必须 32 字节" }
        val out = ByteArray(32)
        X25519.scalarMult(priv, 0, peerPub, 0, out, 0)
        return out
    }

    /**
     * 客户端静态私钥：`a_x_priv = HKDF(salt=app_secret, ikm="jjyv2/v1",
     * info="x25519/client-static", 32)`
     *
     * 注意 salt 与 ikm 的位置 —— 与服务端 `client_static_secret()` 一致。
     */
    fun clientStaticSecret(appSecret: String): ByteArray =
        hkdf(
            salt = appSecret.toByteArray(Charsets.UTF_8),
            ikm = PROTO.toByteArray(Charsets.UTF_8),
            info = CLIENT_STATIC_INFO.toByteArray(Charsets.UTF_8),
        )

    // ── Ed25519 验签（客户端只验，不签） ────────────────────
    fun ed25519Verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pub.size != 32 || sig.size != 64) return false
        return try {
            val v = Ed25519Signer()
            v.init(false, Ed25519PublicKeyParameters(pub, 0))
            v.update(msg, 0, msg.size)
            v.verifySignature(sig)
        } catch (_: Exception) {
            false
        }
    }

    // ── ChaCha20-Poly1305 ───────────────────────────────────
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray {
        val c = ChaCha20Poly1305()
        c.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val out = ByteArray(c.getOutputSize(pt.size))
        val n = c.processBytes(pt, 0, pt.size, out, 0)
        c.doFinal(out, n)
        return out
    }

    /** 解密失败（含 tag 校验失败）返回 null，调用方必须当作拒绝处理。 */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray? {
        return try {
            val c = ChaCha20Poly1305()
            c.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
            val out = ByteArray(c.getOutputSize(ct.size))
            val n = c.processBytes(ct, 0, ct.size, out, 0)
            val total = n + c.doFinal(out, n)
            out.copyOf(total)
        } catch (_: Exception) {
            null
        }
    }

    // ── 报文附加数据 ────────────────────────────────────────
    /** nonce = 4 字节 0 ‖ seq 大端 8 字节 */
    fun seqNonce(seq: Long): ByteArray {
        val n = ByteArray(12)
        for (i in 0 until 8) {
            n[4 + i] = ((seq ushr (56 - i * 8)) and 0xFF).toByte()
        }
        return n
    }

    /** AAD = prefix ‖ sid(UTF-8) ‖ seq 大端 8 字节 */
    fun aad(prefix: String, sid: String, seq: Long): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(prefix.toByteArray(Charsets.UTF_8))
        out.write(sid.toByteArray(Charsets.UTF_8))
        for (i in 0 until 8) {
            out.write(((seq ushr (56 - i * 8)) and 0xFF).toInt())
        }
        return out.toByteArray()
    }

    // ── 会话密钥派生 ────────────────────────────────────────
    class SessionKeys(val c2s: ByteArray, val s2c: ByteArray)

    /**
     * salt = SHA256("jjyv2/v1/salt" ‖ app_key ‖ e_c ‖ e_s ‖ n_c ‖ n_s)
     * ikm  = dh1 ‖ dh2 ‖ dh3
     * c2s  = HKDF(salt, ikm, "c2s", 32)
     * s2c  = HKDF(salt, ikm, "s2c", 32)
     */
    fun deriveSessionKeys(
        appKey: String,
        eC: ByteArray,
        eS: ByteArray,
        nC: ByteArray,
        nS: ByteArray,
        dh1: ByteArray,
        dh2: ByteArray,
        dh3: ByteArray,
    ): SessionKeys {
        val salt = sha256(
            SALT_LABEL.toByteArray(Charsets.UTF_8),
            appKey.toByteArray(Charsets.UTF_8),
            eC, eS, nC, nS,
        )
        val ikm = ByteArrayOutputStream().apply {
            write(dh1); write(dh2); write(dh3)
        }.toByteArray()
        return SessionKeys(
            c2s = hkdf(salt, ikm, "c2s".toByteArray(Charsets.UTF_8)),
            s2c = hkdf(salt, ikm, "s2c".toByteArray(Charsets.UTF_8)),
        )
    }

    // ── 握手 transcript ─────────────────────────────────────
    /**
     * "jjyv2/v1/handshake|{app_key}|{sid}|{b64 e_c}|{b64 n_c}|{b64 e_s}|{b64 n_s}|{ts}"
     */
    fun handshakeTranscript(
        appKey: String, sid: String,
        b64eC: String, b64nC: String, b64eS: String, b64nS: String,
        ts: Long,
    ): ByteArray =
        "$HS_PREFIX|$appKey|$sid|$b64eC|$b64nC|$b64eS|$b64nS|$ts"
            .toByteArray(Charsets.UTF_8)

    // ── 授权票据规范化 ──────────────────────────────────────
    /**
     * "jjyv2/v1/ticket|{v}|{app}|{uid}|{dev}|{iat}|{exp}|{nonce}"
     *
     * dev 缺省替换为空串，exp 缺省同样替换为空串（不是省略整段）。
     */
    fun ticketCanonical(t: Ticket): ByteArray {
        val dev = t.dev ?: ""
        val exp = t.exp?.toString() ?: ""
        return "$TICKET_PREFIX|${t.v}|${t.app}|${t.uid}|$dev|${t.iat}|$exp|${t.nonce}"
            .toByteArray(Charsets.UTF_8)
    }
}
