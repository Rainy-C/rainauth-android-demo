package com.rainauth.demo

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.rainauth.demo.databinding.ActivityMainBinding
import kotlinx.coroutines.launch

/**
 * RainAuth 演示客户端。
 *
 * 两个功能入口，安全属性完全不同 —— 这是本演示最想表达的一点：
 *
 *   「本地功能」  由客户端闸门控制（Kotlin 判定 + native 状态）→ **可破解**
 *   「云端功能」  内容由服务端在核验授权后才下发          → **不可绕过**
 *
 * 破解测试时请分别验证这两条路径，结论会很有说服力。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var store: TicketStore
    private var client: RainAuthClient? = null
    private var deviceId: String = ""

    private val pinnedX by lazy { RainCrypto.b64d(Config.pinnedX25519B64) }
    private val pinnedE by lazy { RainCrypto.b64d(Config.pinnedEd25519B64) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        store = TicketStore(this)
        deviceId = DeviceId.get(this)

        b.tvDevice.text = "设备标识  $deviceId"
        b.tvModel.text = "机型      ${DeviceId.model()}"
        b.tvNative.text = "原生闸门  ${runCatching { RainGuard.nativeVersion() }.getOrDefault("加载失败")}"

        if (DeviceId.looksTampered()) {
            log("⚠ 环境特征异常（模拟器/测试签名），仅提示，不影响流程")
        }

        if (!Config.isConfigured) {
            log("未配置接入参数。请在 gradle.properties 或 CI 变量里填入：")
            log("  RAINAUTH_BASE_URL / RAINAUTH_APP_KEY / RAINAUTH_APP_SECRET")
            log("  RAINAUTH_X25519_PUB / RAINAUTH_ED25519_PUB")
            b.btnActivate.isEnabled = false
        }

        b.btnActivate.setOnClickListener { activate() }
        b.btnLocal.setOnClickListener { localFeature() }
        b.btnCloud.setOnClickListener { cloudFeature() }
        b.btnClear.setOnClickListener { clearAll() }

        refreshUi()
    }

    // ── 激活：握手 + 提交卡密 ──────────────────────────────
    private fun activate() {
        val card = b.etCard.text?.toString()?.trim().orEmpty()
        if (card.isEmpty()) {
            log("请先填入卡密")
            return
        }
        setBusy(true)
        lifecycleScope.launch {
            try {
                val c = RainAuthClient(
                    Config.baseUrl, Config.appKey, Config.appSecret, pinnedX, pinnedE,
                )
                log("→ 握手 ${Config.baseUrl}/hs")

                c.handshake().onFailure {
                    log("✘ 握手失败：${it.message}")
                    return@launch
                }
                log("✔ 握手完成，服务端身份签名校验通过")
                log("  sid = ${c.sessionId}")

                log("→ 提交卡密（设备 $deviceId）")
                val r = c.verify(card = card, device = deviceId, deviceName = DeviceId.model())
                    .getOrElse {
                        log("✘ 请求失败：${it.message}")
                        return@launch
                    }

                if (!r.ok) {
                    log("✘ 验证被拒：${r.msg}")
                    // 服务端拒绝 → 明确上锁，不保留任何上一次的解锁状态
                    lockLocal()
                    return@launch
                }

                log("✔ 验证通过${if (r.activatedNow) "（首次激活）" else ""}")
                log("  授权到期  ${r.expireAt ?: "永久"}")
                log("  设备占用  ${r.deviceUsed}/${r.deviceMax}")

                client = c
                val t = r.ticket
                if (t == null) {
                    log("⚠ 服务端未返回票据，仅本次会话有效")
                } else {
                    store.save(t)
                    log("✔ 已保存授权票据（本地加密存储）")
                    unlockFromTicket(t)
                }
                refreshUi()
            } finally {
                setBusy(false)
            }
        }
    }

    /**
     * 用票据解锁本地闸门。
     *
     * ⚠️ 这里做的上下文校验（应用归属 / 设备归属 / 签发时间）是客户端
     * **自愿**做的。攻击者可以把这段整个删掉，直接调
     * `RainGuard.nativeUnlock(byteArrayOf(), true, true, Long.MAX_VALUE)`。
     * 所以它只提高成本，不构成保证。
     */
    private fun unlockFromTicket(t: Ticket) {
        val (sigOk, why) = RainAuthClient.verifyTicketOffline(t, pinnedE)
        if (!sigOk) {
            log("✘ 票据校验失败：$why")
            lockLocal()
            return
        }
        if (t.app != Config.appKey) {
            log("✘ 票据属于其它应用（${t.app}），拒绝")
            lockLocal()
            return
        }
        val bound = t.dev == deviceId
        if (!bound) {
            log("✘ 票据未绑定本设备（票据 dev=${t.dev ?: "无"}）")
            lockLocal()
            return
        }
        if (!RainGuard.nativeCheckIntegrity()) {
            log("✘ 原生库完整性校验失败，拒绝解锁")
            lockLocal()
            return
        }
        val ok = RainGuard.nativeUnlock(
            RainCrypto.ticketCanonical(t), sigOk, bound, t.exp ?: 0L,
        )
        log(if (ok) "✔ 本地闸门已解锁（状态保存在 so 内）" else "✘ 解锁被原生层拒绝")
    }

    // ── 本地功能：客户端闸门 ───────────────────────────────
    private fun localFeature() {
        if (!RainGuard.nativeIsUnlocked()) {
            log("✘ [本地功能] 未授权 —— 闸门在 native 层，未解锁")
            return
        }
        val payload = RainGuard.nativeFeaturePayload()
        log("✔ [本地功能] 已解锁，载荷：$payload")
        log("  ⚠ 这个载荷的明文就在 APK 里，strings 一下就能拿到")
    }

    // ── 云端功能：服务端核验后才下发 ───────────────────────
    private fun cloudFeature() {
        val c = client
        if (c == null) {
            log("✘ [云端功能] 需要先完成一次在线验证（本地票据不足以取得服务端资源）")
            return
        }
        setBusy(true)
        lifecycleScope.launch {
            try {
                // 关键：不信任任何本地状态，重新向服务端提交一次验证。
                // 服务端独立判定授权，客户端怎么改都影响不了它的结论。
                val r = c.verify(device = deviceId, deviceName = DeviceId.model())
                    .getOrElse {
                        log("✘ [云端功能] 请求失败：${it.message}")
                        return@launch
                    }
                if (!r.ok) {
                    log("✘ [云端功能] 服务端拒绝：${r.msg}")
                    lockLocal()
                    return@launch
                }
                log("✔ [云端功能] 服务端核验通过（server_time=${r.serverTime}）")
                log("  这一条无法通过修改客户端绕过：结论由服务端给出")
            } finally {
                setBusy(false)
            }
        }
    }

    private fun lockLocal() {
        RainGuard.nativeLock()
        refreshUi()
    }

    private fun clearAll() {
        store.clear()
        client = null
        lockLocal()
        log("已清除本地票据与解锁状态")
        refreshUi()
    }

    private fun refreshUi() {
        val unlocked = runCatching { RainGuard.nativeIsUnlocked() }.getOrDefault(false)
        val hasTicket = store.hasValid()
        b.tvState.text = when {
            unlocked -> "状态  已授权（本地闸门已解锁）"
            hasTicket -> "状态  存有票据但未解锁（重启后需重新验证）"
            else -> "状态  未授权"
        }
        b.tvState.setTextColor(
            if (unlocked) 0xFF1B5E20.toInt() else 0xFF8A1C1C.toInt()
        )
    }

    private fun setBusy(busy: Boolean) {
        b.progress.visibility = if (busy) View.VISIBLE else View.GONE
        b.btnActivate.isEnabled = !busy && Config.isConfigured
        b.btnLocal.isEnabled = !busy
        b.btnCloud.isEnabled = !busy
    }

    private fun log(s: String) {
        b.tvLog.append(s + "\n")
        b.scroll.post { b.scroll.fullScroll(View.FOCUS_DOWN) }
    }
}
