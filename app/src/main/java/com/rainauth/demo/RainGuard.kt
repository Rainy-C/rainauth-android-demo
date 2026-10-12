package com.rainauth.demo

/**
 * 原生（C++）许可闸门。
 *
 * 设计意图：把「已解锁」这个状态**从 Kotlin 层挪走**，让简单的
 * `const/4 v0, 0x1` 补丁不再够用 —— 攻击者必须同时改 Java 层判定
 * 和 so 里的状态/校验。
 *
 * ⚠️ **这不是安全边界，只是提高成本。**
 * 任何在用户设备上运行的代码都可被分析、调试、修改。这个类存在的意义是
 * 让「破解」从 5 分钟变成半小时，而不是让它不可能。绕过方式至少有：
 *   1. Hook `nativeIsUnlocked()` 的返回值（Frida / Xposed）
 *   2. 直接 patch `librainguard.so` 里返回状态的汇编
 *   3. 绕过整个闸门，直接调用 `nativeFeaturePayload()` 或自己实现功能
 *   4. 把 so 换成自己的实现
 *
 * 参考 README「可被攻破的部分」。
 */
object RainGuard {

    init {
        System.loadLibrary("rainguard")
    }

    /**
     * 提交票据信息解锁。
     *
     * @param ticketCanonical 票据规范化字节（供 native 侧独立摘要）
     * @param sigOk Kotlin 层的验签结果 —— native 会复核，但不信任它是唯一依据
     * @param deviceBound native 侧重新计算设备绑定摘要
     * @param expEpoch 到期时间戳，0 表示永久
     */
    external fun nativeUnlock(
        ticketCanonical: ByteArray,
        sigOk: Boolean,
        deviceBound: Boolean,
        expEpoch: Long,
    ): Boolean

    /** 闸门状态（保存在 so 的静态区，不在 Kotlin 侧） */
    external fun nativeIsUnlocked(): Boolean

    /** 上锁 */
    external fun nativeLock()

    /**
     * 取受保护功能的载荷。
     * 只有在 native 侧处于解锁状态时才返回内容，否则返回空串。
     */
    external fun nativeFeaturePayload(): String

    /** so 自校验：代码段摘要 + 关键常量比对，失败说明二进制被改过 */
    external fun nativeCheckIntegrity(): Boolean

    /** 原生库版本，便于排查 */
    external fun nativeVersion(): String
}
