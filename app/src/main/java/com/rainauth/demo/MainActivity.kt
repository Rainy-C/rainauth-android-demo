package com.rainauth.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.rainauth.demo.databinding.ActivityMainBinding
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * RainAuth 演示客户端。
 *
 * 三块展示区：
 *   ① 公告        —— 来自 /client/announce
 *   ② 版本        —— 来自 /client/version
 *   ③ 授权卡片    —— 协议验证结果，结构化渲染
 * 外加一块「原始数据」，按标签页切换查看各阶段真实报文。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var store: TicketStore
    private var deviceId = ""
    private var lastReport = ""

    /** 原始报文快照：标题 → 内容 */
    private val rawPages = linkedMapOf<String, String>()
    private var rawIndex = 0

    private val pinnedX by lazy { RainCrypto.b64d(Config.pinnedX25519B64) }
    private val pinnedE by lazy { RainCrypto.b64d(Config.pinnedEd25519B64) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        store = TicketStore(this)
        deviceId = DeviceId.get(this)

        b.btnVerify.setOnClickListener { verify() }
        b.btnCopy.setOnClickListener { copyReport() }
        b.btnToggleRaw.setOnClickListener { toggleRaw() }

        // 启动即拉公告与版本（不需要卡密）
        loadAnnounceAndVersion()
    }

    // ══ 公告 + 版本 ════════════════════════════════════════
    private fun loadAnnounceAndVersion() {
        if (!Config.isConfigured) return
        lifecycleScope.launch {
            RainApi.announcements(Config.baseUrl, Config.appKey)
                .onSuccess { showAnnouncements(it) }
                .onFailure { /* 公告失败不打扰用户 */ }

            RainApi.version(Config.baseUrl, Config.appKey, BuildConfig.VERSION_NAME)
                .onSuccess { showVersion(it) }
                .onFailure { }
        }
    }

    private fun showAnnouncements(list: List<Announce>) {
        if (list.isEmpty()) {
            b.announceBox.visibility = View.GONE
            return
        }
        b.announceList.removeAllViews()
        list.take(5).forEachIndexed { i, a ->
            val tv = TextView(this).apply {
                text = buildString {
                    if (a.title.isNotBlank()) append(a.title).append('\n')
                    append(a.content)
                    append("\n")
                    append(fmtDate(a.createdAt))
                    if (a.global) append("  ·  全局")
                }
                textSize = 13f
                setTextColor(0xFF5C3D00.toInt())
                setLineSpacing(dp(3).toFloat(), 1f)
                setTextIsSelectable(true)
            }
            if (i > 0) {
                val d = View(this).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT, dp(1)
                    ).also { it.topMargin = dp(10); it.bottomMargin = dp(10) }
                    setBackgroundColor(0x33A07400)
                }
                b.announceList.addView(d)
            }
            b.announceList.addView(tv)
        }
        b.announceBox.visibility = View.VISIBLE
    }

    private fun showVersion(v: VersionInfo) {
        b.versionBox.visibility = View.VISIBLE
        if (!v.hasUpdate) {
            b.tvVersionTitle.text = "已是最新版本"
            b.tvVersionBody.text = "当前版本  ${v.current}"
            b.versionBox.setBackgroundColor(0xFFE8F5E9.toInt())
            b.tvVersionTitle.setTextColor(0xFF1B5E20.toInt())
            b.tvVersionBody.setTextColor(0xFF1B5E20.toInt())
            return
        }
        b.versionBox.setBackgroundColor(0xFFE3F2FD.toInt())
        b.tvVersionTitle.setTextColor(0xFF0D47A1.toInt())
        b.tvVersionBody.setTextColor(0xFF0D47A1.toInt())
        b.tvVersionTitle.text = if (v.forceUpdate) "发现新版本（强制更新）" else "发现新版本"
        b.tvVersionBody.text = buildString {
            appendLine("当前版本  ${v.current}")
            appendLine("最新版本  ${v.latest ?: "-"}")
            v.changelog?.let { appendLine("更新说明  $it") }
            appendLine()
            append("注意：has_update 由服务端做字符串不等比较，")
            append("不是语义化版本大小比较 —— 换回旧版本号同样会提示更新。")
        }
        if (v.downloadUrl != null) {
            b.tvVersionBody.setOnClickListener {
                runCatching {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(v.downloadUrl)))
                }
            }
        }
    }

    // ══ 验证 ══════════════════════════════════════════════
    private fun verify() {
        val card = b.etCard.text?.toString()?.trim().orEmpty()
        if (card.isEmpty()) {
            toast("请输入卡密")
            return
        }
        b.progress.visibility = View.VISIBLE
        b.btnVerify.isEnabled = false
        b.card.visibility = View.GONE

        lifecycleScope.launch {
            try {
                val client = RainAuthClient(
                    Config.baseUrl, Config.appKey, Config.appSecret, pinnedX, pinnedE,
                )
                client.handshake().onFailure {
                    collectRaw(client)
                    showError("连接失败", it.message ?: "无法建立安全会话")
                    return@launch
                }
                val r = client.verify(
                    card = card, device = deviceId, deviceName = DeviceId.model(),
                ).getOrElse {
                    collectRaw(client)
                    showError("请求失败", it.message ?: "未知错误")
                    return@launch
                }
                collectRaw(client)

                if (!r.ok) {
                    showError("验证未通过", r.msg.ifBlank { "服务端拒绝了本次验证" })
                    return@launch
                }
                r.ticket?.let { t ->
                    store.save(t)
                    val (sigOk, why) = RainAuthClient.verifyTicketOffline(t, pinnedE)
                    // 票据上下文校验是客户端自愿做的，patch 掉即可绕过 ——
                    // 这里保留是为了让示例流程完整，不是安全边界。
                    val bound = t.dev == deviceId
                    // 运行时环境检查（真的执行，不是空壳）
                    val clean = runCatching { RainGuard.nativeCheckIntegrity(true) }
                        .getOrDefault(false)
                    runCatching {
                        RainGuard.nativeUnlock(
                            RainCrypto.ticketCanonical(t), sigOk, bound && clean, t.exp ?: 0L,
                        )
                    }
                }
                showSuccess(card, r)
            } finally {
                b.progress.visibility = View.GONE
                b.btnVerify.isEnabled = true
            }
        }
    }

    // ══ 授权卡片 ══════════════════════════════════════════
    private fun showSuccess(card: String, r: VerifyResult) {
        val unlocked = runCatching { RainGuard.nativeIsUnlocked() }.getOrDefault(false)

        b.card.setBackgroundColor(0xFFEBDCFF.toInt())
        b.divider.setBackgroundColor(0xFFC9B8E8.toInt())
        b.tvIcon.text = "✓"
        b.tvIcon.setTextColor(0xFF503C74.toInt())
        b.tvStatus.text = if (r.activatedNow) "激活成功" else "授权有效"
        b.tvStatus.setTextColor(0xFF503C74.toInt())

        val expText = r.expireAt?.let { fmt(it) } ?: "永久有效"
        val remainText = r.expireAt?.let { remain(it) } ?: "—"
        val devText = "${r.deviceUsed ?: "-"} / ${r.deviceMax ?: "-"}"

        b.rows.removeAllViews()
        addRow("卡密", card)
        addRow("到期时间", expText, highlight = isNearExpiry(r.expireAt))
        addRow("剩余时长", remainText, highlight = isNearExpiry(r.expireAt))
        addRow("设备占用", devText)
        addRow("用户 ID", r.userId?.toString() ?: "-")
        addRow("本机标识", deviceId)
        addRow("本地闸门", if (unlocked) "已解锁" else "未解锁")

        lastReport = buildString {
            appendLine("RainAuth 授权信息")
            appendLine("──────────────")
            appendLine("卡密      $card")
            appendLine("到期时间  $expText")
            appendLine("剩余时长  $remainText")
            appendLine("设备占用  $devText")
            appendLine("用户 ID   ${r.userId ?: "-"}")
            appendLine("本机标识  $deviceId")
            appendLine("本地闸门  ${if (unlocked) "已解锁" else "未解锁"}")
            appendLine("服务器时间 ${r.serverTime ?: "-"}")
        }
        b.card.visibility = View.VISIBLE
        renderRaw()
    }

    private fun showError(title: String, detail: String) {
        runCatching { RainGuard.nativeLock() }

        b.card.setBackgroundColor(0xFFFFDAD6.toInt())
        b.divider.setBackgroundColor(0xFFF0B7B0.toInt())
        b.tvIcon.text = "✗"
        b.tvIcon.setTextColor(0xFF93000A.toInt())
        b.tvStatus.text = title
        b.tvStatus.setTextColor(0xFF93000A.toInt())

        b.rows.removeAllViews()
        addRowText(detail, 0xFF7A1C14.toInt())

        lastReport = "$title\n\n$detail"
        b.card.visibility = View.VISIBLE
        renderRaw()
    }

    // ══ 原始数据 ══════════════════════════════════════════
    private fun collectRaw(c: RainAuthClient) {
        rawPages.clear()
        if (c.rawHsRequest.isNotBlank()) rawPages["握手请求"] = c.rawHsRequest
        if (c.rawHsResponse.isNotBlank()) rawPages["握手响应"] = c.rawHsResponse
        if (c.rawVerifyRequest.isNotBlank()) rawPages["验证请求"] = c.rawVerifyRequest
        if (c.rawVerifyResponse.isNotBlank()) rawPages["验证响应"] = c.rawVerifyResponse
        if (c.rawInnerReply.isNotBlank()) rawPages["解密回包"] = c.rawInnerReply
        if (c.rawTicket.isNotBlank()) rawPages["授权票据"] = c.rawTicket
        rawIndex = rawPages.keys.indexOf("解密回包").takeIf { it >= 0 } ?: 0
    }

    private fun renderRaw() {
        if (rawPages.isEmpty()) {
            b.rawBox.visibility = View.GONE
            return
        }
        b.rawBox.visibility = View.VISIBLE

        // 标签页
        b.rawTabs.removeAllViews()
        rawPages.keys.forEachIndexed { i, name ->
            val tv = TextView(this).apply {
                text = name
                textSize = 11.5f
                setPadding(dp(10), dp(5), dp(10), dp(5))
                setOnClickListener {
                    rawIndex = i
                    renderRaw()
                }
                if (i == rawIndex) {
                    setTextColor(0xFF1D1B20.toInt())
                    setBackgroundColor(0xFFD0BCFF.toInt())
                } else {
                    setTextColor(0xFFCFC4DC.toInt())
                }
            }
            b.rawTabs.addView(tv)
            b.rawTabs.addView(View(this).apply {
                layoutParams = LinearLayout.LayoutParams(dp(6), 1)
            })
        }

        val name = rawPages.keys.elementAtOrNull(rawIndex) ?: return
        b.tvRaw.text = JsonPretty.format(rawPages[name] ?: "")
    }

    private fun toggleRaw() {
        val showing = b.rawScroll.visibility == View.VISIBLE
        b.rawScroll.visibility = if (showing) View.GONE else View.VISIBLE
        b.rawTabs.visibility = if (showing) View.GONE else View.VISIBLE
        b.btnToggleRaw.text = getString(
            if (showing) R.string.raw_expand else R.string.raw_collapse
        )
    }

    // ══ 视图工具 ══════════════════════════════════════════
    private fun addRow(label: String, value: String, highlight: Boolean = false) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            setPadding(0, dp(7), 0, dp(7))
        }
        row.addView(TextView(this).apply {
            text = label
            textSize = 13f
            setTextColor(0xFF7A6E93.toInt())
            layoutParams = LinearLayout.LayoutParams(dp(74), LinearLayout.LayoutParams.WRAP_CONTENT)
        })
        row.addView(TextView(this).apply {
            text = value
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 13.5f
            setTextColor(if (highlight) 0xFF93000A.toInt() else 0xFF33284A.toInt())
            setTextIsSelectable(true)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        })
        b.rows.addView(row)
    }

    private fun addRowText(text: String, color: Int) {
        b.rows.addView(TextView(this).apply {
            this.text = text
            textSize = 13.5f
            setTextColor(color)
            setTextIsSelectable(true)
            setPadding(0, dp(6), 0, dp(6))
        })
    }

    private fun copyReport() {
        if (lastReport.isBlank()) return
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("RainAuth 授权信息", lastReport))
        toast("已复制到剪贴板")
    }

    // ══ 时间工具 ══════════════════════════════════════════
    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    private fun parseIso(iso: String): Long? {
        val m = Regex("""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""").find(iso)
        return try {
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)
                .parse(m?.groupValues?.get(1) ?: iso)?.time
        } catch (_: Exception) {
            null
        }
    }

    private fun fmt(iso: String): String {
        val t = parseIso(iso) ?: return iso.take(16).replace("T", " ")
        return SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.CHINA).format(Date(t))
    }

    private fun fmtDate(iso: String): String {
        val t = parseIso(iso) ?: return iso.take(10)
        return SimpleDateFormat("yyyy-MM-dd", Locale.CHINA).format(Date(t))
    }

    private fun remain(iso: String): String {
        val end = parseIso(iso) ?: return "—"
        val ms = end - System.currentTimeMillis()
        if (ms <= 0) return "已过期"
        val d = ms / 86400000
        val h = (ms % 86400000) / 3600000
        val m = (ms % 3600000) / 60000
        return when {
            d > 0 -> "$d 天 $h 小时"
            h > 0 -> "$h 小时 $m 分"
            else -> "$m 分钟"
        }
    }

    private fun isNearExpiry(iso: String?): Boolean {
        val end = iso?.let { parseIso(it) } ?: return false
        return end - System.currentTimeMillis() < 3L * 86400000
    }
}
