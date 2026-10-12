package com.rainauth.demo

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
 * RainAuth 演示客户端 —— 输入卡密、验证、展示授权信息。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var store: TicketStore
    private var deviceId = ""
    private var lastReport = ""

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
    }

    // ── 验证流程 ────────────────────────────────────────────
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
                    showError("连接失败", it.message ?: "无法建立安全会话")
                    return@launch
                }
                val r = client.verify(
                    card = card, device = deviceId, deviceName = DeviceId.model(),
                ).getOrElse {
                    showError("请求失败", it.message ?: "未知错误")
                    return@launch
                }
                if (!r.ok) {
                    showError("验证未通过", r.msg.ifBlank { "服务端拒绝了本次验证" })
                    return@launch
                }

                // 票据落盘 + 解锁本地闸门
                r.ticket?.let { t ->
                    store.save(t)
                    val (sigOk, _) = RainAuthClient.verifyTicketOffline(t, pinnedE)
                    runCatching {
                        RainGuard.nativeUnlock(
                            RainCrypto.ticketCanonical(t), sigOk, t.dev == deviceId, t.exp ?: 0L,
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

    // ── 成功卡片 ────────────────────────────────────────────
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
        addRow("到期时间", expText, highlight = true)
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
    }

    // ── 失败卡片 ────────────────────────────────────────────
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
    }

    // ── 行构造 ──────────────────────────────────────────────
    private fun addRow(label: String, value: String, highlight: Boolean = false) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.TOP
            setPadding(0, dp(7), 0, dp(7))
        }
        val tvLabel = TextView(this).apply {
            text = label
            setTextAppearance(com.google.android.material.R.style.TextAppearance_Material3_BodySmall)
            textSize = 13f
            setTextColor(0xFF7A6E93.toInt())
            layoutParams = LinearLayout.LayoutParams(dp(74), LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        val tvValue = TextView(this).apply {
            text = value
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 13.5f
            setTextColor(if (highlight) 0xFF93000A.toInt() else 0xFF33284A.toInt())
            setTextIsSelectable(true)
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        row.addView(tvLabel)
        row.addView(tvValue)
        b.rows.addView(row)
    }

    private fun addRowText(text: String, color: Int) {
        val tv = TextView(this).apply {
            this.text = text
            textSize = 13.5f
            setTextColor(color)
            setTextIsSelectable(true)
            setPadding(0, dp(6), 0, dp(6))
        }
        b.rows.addView(tv)
    }

    // ── 复制 ────────────────────────────────────────────────
    private fun copyReport() {
        if (lastReport.isBlank()) return
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("RainAuth 授权信息", lastReport))
        toast("已复制到剪贴板")
    }

    // ── 工具 ────────────────────────────────────────────────
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

    private fun remain(iso: String): String {
        val end = parseIso(iso) ?: return "—"
        val ms = end - System.currentTimeMillis()
        if (ms <= 0) return "已过期"
        val d = ms / 86400000
        val h = (ms % 86400000) / 3600000
        val m = (ms % 3600000) / 60000
        return if (d > 0) "$d 天 $h 小时" else if (h > 0) "$h 小时 $m 分" else "$m 分钟"
    }

    /** 剩余不足 3 天时用醒目色提示 */
    private fun isNearExpiry(iso: String?): Boolean {
        val end = iso?.let { parseIso(it) } ?: return false
        return end - System.currentTimeMillis() < 3L * 86400000
    }
}
