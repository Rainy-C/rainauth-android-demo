# RainAuth 雨验 · Android 演示客户端

接入 `jjyv2/v1` 端到端加密协议的最小可用 Android 客户端，**同时是一个刻意留出的破解靶子**。

用于回答一个具体问题：

> 客户端能被破解到什么程度？破解之后，攻击者还能拿到什么？

---

## 它做什么

```
输入卡密
   │
   ▼
① 握手  POST /api/v1/hs     三重 X25519 DH + 服务端 Ed25519 签名自证
   │                         客户端用写死的公钥验签，失败即终止
   ▼
② 验证  POST /api/v1/verify  ChaCha20-Poly1305 加密信封，seq 严格递增
   │                         服务端返回授权结果 + Ed25519 签名票据
   ▼
③ 票据  本地加密存储         可离线验签，含设备绑定与到期时间
   │
   ▼
④ 闸门  原生（C++）状态机    解锁后才放行「本地功能」
```

两个功能入口，**安全属性完全不同**：

| 入口 | 判定位置 | 能否破解 |
|---|---|---|
| 本地功能 | 客户端（Kotlin 判定 + so 内状态） | ✅ **能** |
| 云端功能 | 服务端独立核验后下发 | ❌ **不能** |

---

## 构建

### GitHub Actions（推荐）

推送即构建，产物在 Actions 页面的 Artifacts 里，含 debug 与 release 两个 APK。

接入参数通过 **Repository Secrets** 注入（`Settings → Secrets and variables → Actions`）：

```
RAINAUTH_BASE_URL     https://rain.example.com/api/v1
RAINAUTH_APP_KEY      <应用 app_key>
RAINAUTH_APP_SECRET   <应用 app_secret>
RAINAUTH_X25519_PUB   <本应用 X25519 公钥，base64>
RAINAUTH_ED25519_PUB  <本应用 Ed25519 公钥，base64>
```

**一个都不配也能构建成功** —— App 启动后会提示「未配置」，不会崩溃。

### 本地

```bash
# 在 gradle.properties 里填入上面五项（别提交）
./gradlew assembleDebug        # 调试包
./gradlew assembleRelease      # 发布包（R8 混淆 + 资源压缩）
```

产物：`app/build/outputs/apk/{debug,release}/`

公钥在开发者控制台查看，或直接问服务端：

```bash
cd server && ./jjy-server keys        # 打印 identity_pub / license_pub
```

⚠️ 注意区分：`identity_pub` / `license_pub` 是**服务端全局**密钥；
本应用还需要自己的 `x25519_public` / `ed25519_public`，从应用详情接口取。

---

## 加固清单（做了什么）

| 项 | 实现 |
|---|---|
| 协议 | X25519 / Ed25519 / ChaCha20-Poly1305 / HKDF-SHA256，与 Rust 服务端逐字节一致 |
| 服务端身份 | 公钥**写死在 APK**，握手验签失败直接终止会话，不做任何降级 |
| 传输 | OkHttp 默认证书校验，`network_security_config` 禁止明文流量 |
| 票据存储 | `EncryptedSharedPreferences`（密钥由 Android Keystore 托管） |
| 许可状态 | 保存在 **native so 的静态区**，不在 Kotlin 侧 |
| 混淆 | R8（`isMinifyEnabled` + `isShrinkResources`） |
| 原生 | `-fvisibility=hidden`、`--gc-sections`、`-z relro,now`、`noexecstack`、发布包 strip |
| 自校验 | 原生常量表 CRC + 编译期比对 |

体积：debug 11 MB，release 3.2 MB。

---

## ⚠️ 可被攻破的部分

**这些是设计如此，不是缺陷。** 请逐条尝试，都能成功：

### 1. 直接改闸门判定

```kotlin
// MainActivity.localFeature()
if (!RainGuard.nativeIsUnlocked()) { ... }   // ← 把这个 if 删掉
```

或在 native 侧：

```cpp
JNIEXPORT jboolean JNICALL nativeIsUnlocked(...) {
    if (g_state != 1) return JNI_FALSE;      // ← 直接 return JNI_TRUE
```

### 2. Hook JNI 返回值

```javascript
// Frida
Java.perform(function () {
    var G = Java.use("com.rainauth.demo.RainGuard");
    G.nativeIsUnlocked.implementation = function () { return true; };
    G.nativeCheckIntegrity.implementation = function () { return true; };
});
```

**注意**：`nativeIsUnlocked` 是 `native` 方法，Frida 在 Java 层覆写它同样有效 ——
native 状态机挡不住 Java 层 Hook。

### 3. 直接提取载荷

```bash
strings lib/arm64-v8a/librainguard.so | grep -i rain
```

载荷的明文就在 so 里，`nativeFeaturePayload()` 只是按状态返回它。

### 4. 伪造设备标识

`DeviceId` 基于 `ANDROID_ID` 的 SHA-256。root 设备上：

```bash
# 或直接在请求里改 device 字符串
adb shell settings put secure android_id <任意值>
```

顺带一提：**服务端的设备配额也是按这个字符串计的**，
换一个字符串就是「新设备」，能绕过 `max_devices`。

### 5. 绕过票据的上下文校验

`unlockFromTicket()` 里的应用归属 / 设备归属 / 签发时间校验是客户端**自愿**做的：

```kotlin
RainGuard.nativeUnlock(ByteArray(0), true, true, Long.MAX_VALUE)  // 一行绕过
```

### 6. 重打包

改完 smali → 用**自己的签名**重新打包 → 安装。
`demo.keystore` 的密码是明文写在 `build.gradle.kts` 里的，谁都能签。

### 7. 拔掉网络

本地票据一旦落盘，断网也能解锁到票据到期 —— 这是设计要求的离线能力，
也意味着「服务端拉黑」在到期前对本地功能无效。

---

## ❌ 不可绕过的部分

### 云端功能

它**不信任任何客户端状态**，重新向服务端提交一次验证，由服务端独立判定：

```kotlin
// 客户端怎么改都影响不了这个结论
val r = c.verify(device = deviceId, deviceName = DeviceId.model())
if (!r.ok) { /* 服务端说不给，就是不给 */ }
```

破解者可以删掉这段调用，但**删掉之后就没人给他数据了** —— 数据在服务端。

### 伪造服务端

握手与票据都由服务端 Ed25519 签名，公钥写死在 APK 里。
要伪造，必须拿到 `SERVER_MASTER_KEY`（只在服务端内存与 `.env` 里）。
**改客户端改不出这个密钥。**

### 伪造授权票据

同理。票据的规范化字节 + 服务端签名，客户端没有签发私钥。

### 已签发票据的提前吊销

做不到 —— 这是**签名票据的固有限制**，不是实现缺陷。
离线票据在到期前无法被撤销。缓解手段只有：缩短有效期 + 在线时复核。

---

## 破解测试建议的检查顺序

```
[ ] 1. jadx 反编译 release APK，能否直接看出闸门逻辑？        （预期：能）
[ ] 2. Frida Hook nativeIsUnlocked，本地功能是否放行？        （预期：能）
[ ] 3. 改 smali 重打包，用自己的签名安装，能否运行？          （预期：能）
[ ] 4. strings librainguard.so，能否拿到载荷明文？            （预期：能）
[ ] 5. 改 device 字符串，能否绕过服务端设备配额？             （预期：能）
[ ] 6. 断网 + 拷票据到另一台设备，能否解锁？                  （预期：不能，dev 不匹配）
[ ] 7. 伪造服务端响应，能否骗过握手？                         （预期：不能，验签失败）
[ ] 8. 自己签发一张票据，能否通过验签？                       （预期：不能）
[ ] 9. 改客户端，能否取得「云端功能」的数据？                 （预期：不能）
[ ] 10. 删掉整个客户端，直接调 API，能否取得授权？            （预期：不能，无凭据）
```

第 1–5 条会全部成功，第 6–10 条会全部失败。**这个对比就是结论**：

> 客户端防护决定「破解要花多久」，服务端判定决定「破解之后能得到什么」。

---

## 下一步（让第 1–5 条也变难）

| 方向 | 做法 | 效果 |
|---|---|---|
| 设备身份 | Android Keystore 生成不可导出 P-256 密钥，服务端挑战签名 | **device 字符串不再是身份**，第 4 条失效 |
| 完整性证明 | Play Integrity / Key Attestation，服务端独立验证书链 | 改包后服务端可识别，第 3、6 条受限 |
| 服务端下发 | 高价值功能一律服务端给数据 | 第 9 条从"不能"变成"不可能" |
| 票据升级 | 短期在线票据 + 明确的离线宽限期 | 缩短第 7 条的窗口 |
| 原生加固 | 控制流平坦化、代码段哈希远端比对 | 抬高第 1、2 条成本（**不改变结论**） |

**不建议**投入反 Frida / 反调试检测 —— 它跑在攻击者的设备上，绕过成本极低。

---

## 目录

```
app/src/main/
├─ java/com/rainauth/demo/
│   ├─ RainCrypto.kt       密码学原语（与服务端 crypto.rs 对应）
│   ├─ RainAuthClient.kt   握手 / 验证 / 离线验票
│   ├─ RainGuard.kt        原生闸门的 JNI 边界
│   ├─ DeviceId.kt         设备标识（软件指纹，可伪造）
│   ├─ TicketStore.kt      票据本地加密存储
│   ├─ Config.kt           接入参数（构建时注入）
│   └─ MainActivity.kt     界面与流程
└─ cpp/rainguard.cpp       许可状态机 + 自校验
```

---

## 协议参考

| 项 | 值 |
|---|---|
| 版本 | `jjyv2/v1` |
| 套件 | X25519 + Ed25519 + ChaCha20-Poly1305 + HKDF-SHA256 |
| 握手中继文 | `jjyv2/v1/handshake\|{app_key}\|{sid}\|{b64 e_c}\|{b64 n_c}\|{b64 e_s}\|{b64 n_s}\|{ts}` |
| 票据规范化 | `jjyv2/v1/ticket\|{v}\|{app}\|{uid}\|{dev}\|{iat}\|{exp}\|{nonce}` |
| nonce | 4 字节 0 ‖ seq 大端 8 字节 |
| AAD | `jjyv2/v1/c2s`（或 `s2c`）‖ sid ‖ seq 大端 8 字节 |
| 编码 | 标准 base64（含填充）；时间单位**秒**；整数大端 |
