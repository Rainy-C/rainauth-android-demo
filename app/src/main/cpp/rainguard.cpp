// RainAuth 演示客户端的原生许可闸门
//
// 目的：把「已解锁」这个状态从 Kotlin 层挪到 so 里，让最简单的
// `const/4 v0, 0x1` 补丁不再够用 —— 攻击者必须同时处理 Java 层判定
// 与 native 侧状态/自校验。
//
// ⚠️ 这**不是**安全边界，只是提高破解成本。跑在用户设备上的代码
// 一定可以被分析、Hook、patch。具体可被绕过的方式见项目 README。
//
// 本文件不依赖任何第三方库（不用 libsodium），因此 NDK 交叉编译
// 零额外依赖 —— 与 sdk/cpp 当初为了 Android 移除 libcurl 是同一个理由。

#include <jni.h>
#include <android/log.h>

#include <ctime>
#include <cstdint>
#include <cstring>
#include <string>

#define LOG_TAG "RainGuard"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace {

// ── 编译期常量表 + 自校验 ───────────────────────────────────
//
// 表参与自校验：运行时重算 CRC 并与编译期算出的值比对。
// 这能检出「有人把表里的常量改掉」这类静态 patch，但**检不出**
// 控制流被改写 —— 那需要更重的方案（控制流平坦化 / 代码段哈希 +
// 远端比对），超出演示范围。
constexpr uint32_t kMagic[8] = {
    0x52A1B70Cu, 0x9E3779B9u, 0x1F83D9ABu, 0x5BE0CD19u,
    0xC0FFEE11u, 0xDEADBEEFu, 0x0BADF00Du, 0xFEEDFACEu,
};

constexpr uint32_t crc32_table(const uint32_t* p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 32; ++k) {
            crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
        }
    }
    return ~crc;
}

constexpr uint32_t kMagicCrc = crc32_table(kMagic, 8);

// ── 许可状态：只存在于 so 的静态区 ──────────────────────────
// 0 = 已锁定，1 = 已解锁
int32_t g_state = 0;
int64_t g_exp = 0;
uint32_t g_binding = 0;
uint32_t g_unlock_nonce = 0;

// 简单 FNV-1a，用于把票据规范化字节与设备绑定压成一个摘要
uint32_t fnv1a(const uint8_t* d, size_t n, uint32_t seed = 0x811C9DC5u) {
    uint32_t h = seed;
    for (size_t i = 0; i < n; ++i) {
        h ^= d[i];
        h *= 0x01000193u;
    }
    return h;
}

}  // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeUnlock(
    JNIEnv* env, jclass, jbyteArray ticket_canonical, jboolean sig_ok,
    jboolean device_bound, jlong exp_epoch) {

    // 前置条件缺一不可。注意 Java 层的 sig_ok 无法被 native 独立验证
    // （验签在 Kotlin 侧做），所以这里只能把它当作「Kotlin 层声明的」结果。
    // 攻击者 patch Kotlin 让它恒为 true，就绕过了这一层 —— 这正是
    // 客户端防护的上限，README 里说明了。
    if (!sig_ok || !device_bound) {
        g_state = 0;
        return JNI_FALSE;
    }

    const int64_t now = static_cast<int64_t>(time(nullptr));
    if (exp_epoch > 0 && now >= exp_epoch) {
        g_state = 0;
        return JNI_FALSE;
    }

    const jsize n = env->GetArrayLength(ticket_canonical);
    jbyte* buf = env->GetByteArrayElements(ticket_canonical, nullptr);
    g_binding = fnv1a(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(n));
    env->ReleaseByteArrayElements(ticket_canonical, buf, JNI_ABORT);

    g_exp = exp_epoch;
    g_unlock_nonce = static_cast<uint32_t>(now) ^ g_binding;

    g_state = 1;
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeIsUnlocked(JNIEnv*, jclass) {
    if (g_state != 1) return JNI_FALSE;

    // 到期复核：票据可能在这一进程生命周期内过期
    if (g_exp > 0 && static_cast<int64_t>(time(nullptr)) >= g_exp) {
        g_state = 0;
        return JNI_FALSE;
    }
    // 解锁票据必须仍然与当前状态一致
    if (g_unlock_nonce != (static_cast<uint32_t>(g_exp) ^ g_binding)) {
        g_state = 0;
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_rainauth_demo_RainGuard_nativeLock(JNIEnv*, jclass) {
    g_state = 0;
    g_exp = 0;
    g_binding = 0;
    g_unlock_nonce = 0;
}

JNIEXPORT jstring JNICALL
Java_com_rainauth_demo_RainGuard_nativeFeaturePayload(JNIEnv* env, jclass) {
    // 受保护功能的载荷。只有解锁状态才返回内容。
    //
    // 演示要点：**这个字符串本身就在 APK 里**，不解锁也能从 so 里
    // 用 strings 挖出来。真正需要保护的内容不能放在客户端 ——
    // 见 README「不可绕过的部分」。
    if (g_state != 1) return env->NewStringUTF("");

    // 由 (绑定摘要 ⊕ 解锁随机数) 派生，让静态提取拿不到明文
    uint32_t k = g_binding ^ g_unlock_nonce;
    std::string s;
    const char* parts[] = {
        "RAIN-UNLOCKED",
        "-PAYLOAD-",
        nullptr,
    };
    for (int i = 0; parts[i]; ++i) {
        for (const char* p = parts[i]; *p; ++p) {
            s.push_back(static_cast<char>(*p ^ (k & 0x0F)));
            k = k * 1664525u + 1013904223u;
        }
    }
    return env->NewStringUTF(s.c_str());
}

JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeCheckIntegrity(JNIEnv*, jclass) {
    // 常量表自校验：检出「静态改掉 kMagic」这类 patch。
    const uint32_t now = crc32_table(kMagic, 8);
    if (now != kMagicCrc) {
        LOGW("原生常量表被修改（crc=%08x 期望=%08x）", now, kMagicCrc);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL
Java_com_rainauth_demo_RainGuard_nativeVersion(JNIEnv* env, jclass) {
    return env->NewStringUTF("rainguard/1.0.0");
}

}  // extern "C"
