# RainAuth 演示客户端 · R8 规则
#
# 目标：抬高静态阅读成本。
# ⚠️ 混淆不是防护 —— 反混淆工具对这类规则几乎免疫。真正的边界在服务端。

# ── 保留 JNI 边界（名字必须与 native 符号一致） ──────────────
-keepclasseswithmembernames class com.rainauth.demo.RainGuard {
    native <methods>;
}
-keep class com.rainauth.demo.RainGuard { *; }

# ── 保留协议常量：混淆掉也拦不住逆向，但会让字符串搜索变费劲 ──
# （R8 会把字符串常量留在常量池里，这里不做无意义的加密处理）

# ── 移除全部日志（发布包不留调试痕迹） ──────────────────────
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
}
-assumenosideeffects class android.util.Log {
    public static *** println(...);
}

# ── BouncyCastle：只保留用到的算法，其余裁掉 ────────────────
-keep class org.bouncycastle.crypto.digests.SHA256Digest { *; }
-keep class org.bouncycastle.crypto.generators.HKDFBytesGenerator { *; }
-keep class org.bouncycastle.crypto.modes.ChaCha20Poly1305 { *; }
-keep class org.bouncycastle.crypto.signers.Ed25519Signer { *; }
-keep class org.bouncycastle.math.ec.rfc7748.X25519 { *; }
-keep class org.bouncycastle.crypto.params.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**

# ── OkHttp ────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.jsse.**
-dontwarn org.openjsse.**

# ── 行号与源文件信息去掉，栈里不留原始类名 ─────────────────
-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable
