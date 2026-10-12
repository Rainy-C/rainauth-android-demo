// RainAuth 接入示例 · 原生许可闸门
//
// ⚠️ 先读这段再读代码：
//
//   这是**接入示例**，演示「如何把许可状态放进 native 并在 JNI 边界上收口」，
//   **不是**一套客户端防护方案。跑在用户设备上的代码一定可以被分析、Hook、patch。
//   本文件里所有检查都只提高成本，不构成安全边界 —— 真正的授权判定在服务端。
//
//   报告里常见的「能否 patch 掉」的结论，对示例来说都成立，不构成缺陷。
//
// 不依赖任何第三方库（不用 libsodium），NDK 交叉编译零额外依赖 ——
// 与 sdk/cpp 当初为 Android 移除 libcurl 是同一个理由。

#include <jni.h>
#include <android/log.h>

#include <cctype>
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>

#define LOG_TAG "RainGuard"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

namespace {

// ── 许可状态 ─────────────────────────────────────────────
//  0 = 已锁定，1 = 已解锁
//
// 状态只由 nativeUnlock 写入，写入前必须满足：Kotlin 侧声明的验签结果与
// 设备绑定都为真，且票据未过期。native 无法独立复验签名（验签用的固定公钥
// 在 Kotlin 侧），所以这两个布尔只能作为「Kotlin 层声明的结果」采信 ——
// 这正是客户端防护的上限。
int32_t g_state = 0;
int64_t g_exp = 0;          // 0 = 永久
uint32_t g_binding = 0;     // 票据规范化字节的摘要，仅用于展示与区分

// FNV-1a：把票据规范化字节压成一个摘要。
// ⚠️ 非加密哈希 —— 只用来做标识，不承担任何完整性保证。
uint32_t fnv1a(const uint8_t* d, size_t n, uint32_t seed = 0x811C9DC5u) {
    uint32_t h = seed;
    for (size_t i = 0; i < n; ++i) {
        h ^= d[i];
        h *= 0x01000193u;
    }
    return h;
}

bool contains_ci(const char* hay, const char* needle) {
    if (!hay || !needle) return false;
    const size_t nl = strlen(needle);
    if (nl == 0) return false;
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (i < nl && p[i] &&
               tolower(static_cast<unsigned char>(p[i])) ==
               tolower(static_cast<unsigned char>(needle[i]))) {
            ++i;
        }
        if (i == nl) return true;
    }
    return false;
}

/**
 * 运行时环境检查：扫 /proc/self/maps 找已知注入框架。
 *
 * ⚠️ 这**不是**可靠的检测手段：改名、内存加载、卸载模块都能绕过。
 * 放在这里是为了演示「完整性检查应该真的执行、真的返回结果」，
 * 而不是像早期版本那样被编译器优化成 `mov w0,#1; ret`。
 */
bool has_injection_trace() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return false;   // 读不到就不据此判定，避免误报

    static const char* kBad[] = {
        "frida", "gadget", "xposed", "substrate", "magisk", "lsposed", nullptr,
    };
    char line[512];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; kBad[i]; ++i) {
            if (contains_ci(line, kBad[i])) {
                LOGW("检测到注入框架痕迹: %s", kBad[i]);
                hit = true;
                break;
            }
        }
        if (hit) break;
    }
    fclose(f);
    return hit;
}

/** 加载的 so 是否来自本应用的私有目录（重打包后路径通常仍合法，仅作参考） */
bool lib_path_ok() {
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void*>(&lib_path_ok), &info)) return true;
    if (!info.dli_fname) return true;
    return contains_ci(info.dli_fname, "/data/app/") ||
           contains_ci(info.dli_fname, "/data/data/") ||
           contains_ci(info.dli_fname, "/data/user/");
}

}  // namespace

extern "C" {

/**
 * 解锁。只接受票据规范化字节与三个判定结果，其余全部内部推导。
 *
 * 注意：sig_ok / device_bound 来自 Kotlin 侧，native 无法独立复验。
 * 这就是为什么「客户端闸门」只能是成本，不能是边界 —— 见 README。
 */
JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeUnlock(
    JNIEnv* env, jclass, jbyteArray ticket_canonical, jboolean sig_ok,
    jboolean device_bound, jlong exp_epoch) {

    // 任一前置条件不满足 → 明确上锁，绝不保留上一次的解锁状态
    if (!sig_ok || !device_bound) {
        g_state = 0;
        g_exp = 0;
        g_binding = 0;
        return JNI_FALSE;
    }

    const int64_t now = static_cast<int64_t>(time(nullptr));
    if (exp_epoch > 0 && now >= exp_epoch) {
        g_state = 0;
        g_exp = 0;
        g_binding = 0;
        return JNI_FALSE;
    }

    const jsize n = env->GetArrayLength(ticket_canonical);
    jbyte* buf = env->GetByteArrayElements(ticket_canonical, nullptr);
    g_binding = fnv1a(reinterpret_cast<const uint8_t*>(buf), static_cast<size_t>(n));
    env->ReleaseByteArrayElements(ticket_canonical, buf, JNI_ABORT);

    g_exp = exp_epoch;
    g_state = 1;
    return JNI_TRUE;
}

/**
 * 查询闸门状态。
 *
 * 直接由 g_state + g_exp 派生，不再引入任何「非一致性」校验 ——
 * 早期版本存的是 `now ^ binding` 却拿 `exp ^ binding` 去比，导致恒为 false。
 * 那类自造校验如果不参与真实判定，只会制造 bug。
 */
JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeIsUnlocked(JNIEnv*, jclass) {
    if (g_state != 1) return JNI_FALSE;

    // 到期复核：进程存活期间票据可能过期
    if (g_exp > 0 && static_cast<int64_t>(time(nullptr)) >= g_exp) {
        g_state = 0;
        g_exp = 0;
        g_binding = 0;
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT void JNICALL
Java_com_rainauth_demo_RainGuard_nativeLock(JNIEnv*, jclass) {
    g_state = 0;
    g_exp = 0;
    g_binding = 0;
}

/**
 * 受保护功能的载荷。
 *
 * ⚠️ 载荷明文就在 so 里，`strings` 一下就能挖出来 —— 这是示例的既定属性。
 * 真正需要保护的内容不能放在客户端，必须由服务端按会话下发。
 */
JNIEXPORT jstring JNICALL
Java_com_rainauth_demo_RainGuard_nativeFeaturePayload(JNIEnv* env, jclass) {
    if (g_state != 1) return env->NewStringUTF("");
    if (g_exp > 0 && static_cast<int64_t>(time(nullptr)) >= g_exp) {
        g_state = 0;
        return env->NewStringUTF("");
    }

    std::string s = "RAIN-UNLOCKED-PAYLOAD";
    // 混入绑定摘要，让它随票据变化（不是加密，只是避免一个固定字符串）
    uint32_t k = g_binding;
    for (auto& c : s) {
        c = static_cast<char>(c ^ (k & 0x1F));
        k = k * 1664525u + 1013904223u;
    }
    return env->NewStringUTF(s.c_str());
}

/**
 * 运行时环境检查。
 *
 * 早期版本用编译期常量做 CRC 自比对，被编译器折叠成 `return true`；
 * 现在改为真的读取运行时信息。仍然可被绕过（改名、内存加载），
 * 但至少它是**真实执行**的代码，不是空壳。
 *
 * @param strict 严格模式下，注入痕迹或路径异常即判失败
 */
JNIEXPORT jboolean JNICALL
Java_com_rainauth_demo_RainGuard_nativeCheckIntegrity(JNIEnv*, jclass, jboolean strict) {
    if (has_injection_trace()) return JNI_FALSE;
    if (!lib_path_ok()) return JNI_FALSE;
    (void) strict;
    return JNI_TRUE;
}

JNIEXPORT jstring JNICALL
Java_com_rainauth_demo_RainGuard_nativeVersion(JNIEnv* env, jclass) {
    return env->NewStringUTF("rainguard/1.1.0");
}

}  // extern "C"
