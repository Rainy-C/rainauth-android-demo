package com.rainauth.demo

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest

/**
 * 设备标识。
 *
 * ⚠️ **这是软件指纹，不构成任何密码学保证。**
 *
 * 取值来源（第一个能取到的）：
 *  1. `Settings.Secure.ANDROID_ID` —— Android 8+ 起按「应用签名 + 用户」隔离，
 *     重装/换签名会变，但同一签名的 App 可读，root 设备可直接改写。
 *  2. 退化：随机 UUID 存 SharedPreferences（清数据即变）。
 *
 * 服务端只用它做**分组与配额计数**，不作为身份凭据。
 * 「一台设备只能挂 N 张卡」这类规则，防的是无意的多开，挡不住有意伪造：
 * 任何有 root 权限的人都能改 ANDROID_ID，或直接在请求里换一个 device 字符串。
 *
 * 真正不可复制的设备身份需要硬件密钥（Android Keystore + Key Attestation），
 * 见 README「下一步」。
 */
object DeviceId {

    private const val PREF = "rainauth_device"
    private const val KEY_FALLBACK = "fallback_id"

    @SuppressLint("HardwareIds")
    fun get(context: Context): String {
        val raw = androidId(context) ?: fallback(context)
        return sha256Hex("rainauth|${context.packageName}|$raw").take(32)
    }

    private fun androidId(context: Context): String? = try {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?.takeIf { it.isNotBlank() && it != "9774d56d682e549c" }
    } catch (_: Exception) {
        null
    }

    private fun fallback(context: Context): String {
        val sp = context.getSharedPreferences(PREF, Context.MODE_PRIVATE)
        sp.getString(KEY_FALLBACK, null)?.let { return it }
        val id = java.util.UUID.randomUUID().toString()
        sp.edit().putString(KEY_FALLBACK, id).apply()
        return id
    }

    /** 设备型号，仅用于展示与风控参考，不参与授权判定。 */
    fun model(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()

    /** 是否看起来像被改过的环境（仅供参考，**不可作为安全依据**）。 */
    fun looksTampered(): Boolean {
        val tags = (Build.TAGS ?: "").lowercase()
        val fp = (Build.FINGERPRINT ?: "").lowercase()
        return tags.contains("test-keys") ||
                fp.contains("generic") ||
                fp.contains("vbox") ||
                fp.contains("emulator")
    }

    private fun sha256Hex(s: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest(s.toByteArray())
        return d.joinToString("") { "%02x".format(it) }
    }
}
