package com.rainauth.demo

/**
 * 接入配置。
 *
 * 前 4 项由构建时注入（见 `app/build.gradle.kts` 的 buildConfigField），
 * 可在 `gradle.properties` 或 CI 环境变量里覆盖：
 *
 *   RAINAUTH_BASE_URL   https://rain.example.com/api/v1
 *   RAINAUTH_APP_KEY    应用 app_key
 *   RAINAUTH_APP_SECRET 应用 app_secret
 *
 * 公钥**必须**是应用专属那一对，从开发者控制台或服务端 `keys` 接口取得后写死。
 * 「写死」是协议要求的一部分：客户端不该在运行时信任从网络拉来的公钥。
 *
 * ⚠️ 安全边界：`app_secret` 与公钥都在 APK 里，**必然可被提取**。
 * 它们只用于向服务端证明「这是本应用的合法构建」，不构成授权。
 * 真正的授权判定在服务端，见 README「可被攻破的部分」。
 */
object Config {

    /** 服务端 API 基址，含 /api/v1 */
    val baseUrl: String = BuildConfig.RAINAUTH_BASE_URL

    val appKey: String = BuildConfig.RAINAUTH_APP_KEY
    val appSecret: String = BuildConfig.RAINAUTH_APP_SECRET

    /**
     * 固定写入的服务端 X25519 公钥（base64，32 字节）。
     * 用于 dh2 —— 向客户端证明对端持有本应用的静态私钥。
     */
    val pinnedX25519B64: String = BuildConfig.RAINAUTH_X25519_PUB

    /**
     * 固定写入的服务端 Ed25519 公钥（base64，32 字节）。
     * 用于校验握手签名与授权票据签名。
     */
    val pinnedEd25519B64: String = BuildConfig.RAINAUTH_ED25519_PUB

    /** 是否已完成配置（未配置时 App 只显示提示，不发请求） */
    val isConfigured: Boolean
        get() = baseUrl.isNotBlank() &&
                appKey.isNotBlank() &&
                appSecret.isNotBlank() &&
                pinnedX25519B64.isNotBlank() &&
                pinnedEd25519B64.isNotBlank()
}
