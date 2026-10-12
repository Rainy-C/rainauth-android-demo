package com.rainauth.demo

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * 票据本地存储。
 *
 * 用 `EncryptedSharedPreferences`（密钥由 Android Keystore 托管）落盘，
 * 而不是明文 SharedPreferences —— 至少让「直接拷数据文件」这条路不那么直接。
 *
 * ⚠️ 但这也挡不住 root：Keystore 密钥虽然不可导出，root 应用仍可通过
 * Hook 应用进程读解密后的内存。**本地存储的票据本质上不可信**，
 * 服务端不能依赖「客户端本地存了什么」来判断授权。
 */
class TicketStore(context: Context) {

    private val prefs = run {
        val key = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "rainauth_ticket",
            key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    data class Stored(
        val canonical: String,
        val sigB64: String,
        val appKey: String,
        val dev: String?,
        val exp: Long?,
    )

    fun save(t: Ticket) {
        prefs.edit()
            .putString(K_CANONICAL, String(RainCrypto.ticketCanonical(t)))
            .putString(K_SIG, RainCrypto.b64e(t.sig))
            .putString(K_APP, t.app)
            .putString(K_DEV, t.dev ?: "")
            .putLong(K_EXP, t.exp ?: 0L)
            .apply()
    }

    fun load(): Stored? {
        val canonical = prefs.getString(K_CANONICAL, null) ?: return null
        val sig = prefs.getString(K_SIG, null) ?: return null
        val exp = prefs.getLong(K_EXP, 0L)
        return Stored(
            canonical = canonical,
            sigB64 = sig,
            appKey = prefs.getString(K_APP, "") ?: "",
            dev = prefs.getString(K_DEV, "")?.takeIf { it.isNotEmpty() },
            exp = exp.takeIf { it > 0 },
        )
    }

    fun clear() = prefs.edit().clear().apply()

    /** 供展示：是否存有未过期票据 */
    fun hasValid(): Boolean {
        val s = load() ?: return false
        val e = s.exp ?: return true
        return e > System.currentTimeMillis() / 1000
    }

    private companion object {
        const val K_CANONICAL = "canonical"
        const val K_SIG = "sig"
        const val K_APP = "app"
        const val K_DEV = "dev"
        const val K_EXP = "exp"
    }
}
