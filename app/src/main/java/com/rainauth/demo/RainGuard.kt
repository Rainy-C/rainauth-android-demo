package com.rainauth.demo

/**
 * 原生（C++）许可闸门 —— **接入示例**。
 *
 * 演示的是「怎么把许可状态放进 native、在 JNI 边界上收口」，
 * **不是**一套客户端防护方案。
 *
 * ⚠️ 必须清楚它的能力边界：
 *   - `nativeUnlock` 的入参里有 Kotlin 侧算出的两个布尔（验签结果、设备绑定）。
 *     native **无法独立复验**签名 —— 验签需要的固定公钥在 Kotlin 侧。
 *     所以 patch Kotlin 让它们恒为 true，就能直接解锁。
 *   - `nativeIsUnlocked` 是 native 里的一个可写全局 + 布尔返回，
 *     两条指令即可改成恒真（Frida Hook 或直接 patch so）。
 *   - `nativeFeaturePayload` 的载荷明文就在 so 里，`strings` 就能挖出来。
 *
 * 这些都是**示例的既定属性**，见项目 README「这是接入示例」一节。
 * 任何在用户设备上运行的代码都无法成为可信执行环境 ——
 * 真正需要保护的数据必须由服务端按授权下发。
 */
object RainGuard {

    init {
        System.loadLibrary("rainguard")
    }

    /**
     * 提交票据信息解锁。
     *
     * @param ticketCanonical 票据规范化字节（native 侧压成摘要，仅作标识）
     * @param sigOk           Kotlin 侧 Ed25519 验签结果
     * @param deviceBound     Kotlin 侧设备绑定判定结果
     * @param expEpoch        到期时间戳，0 表示永久
     */
    external fun nativeUnlock(
        ticketCanonical: ByteArray,
        sigOk: Boolean,
        deviceBound: Boolean,
        expEpoch: Long,
    ): Boolean

    /** 闸门状态。由 native 的 g_state + 到期时间派生。 */
    external fun nativeIsUnlocked(): Boolean

    /** 上锁，清空全部状态 */
    external fun nativeLock()

    /** 受保护功能的载荷。仅在解锁且未过期时返回内容。 */
    external fun nativeFeaturePayload(): String

    /**
     * 运行时环境检查：扫 /proc/self/maps 找注入框架痕迹 + 校验 so 加载路径。
     *
     * @param strict 严格模式。目前两种模式行为一致，保留参数以便后续区分。
     */
    external fun nativeCheckIntegrity(strict: Boolean): Boolean

    /** 原生库版本 */
    external fun nativeVersion(): String
}
