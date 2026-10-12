package com.rainauth.demo

import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.rainauth.demo.databinding.ActivityMainBinding
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * RainAuth 演示客户端 —— 输入卡密、验证、显示结果。
 *
 * 验证通过后本地闸门解锁（状态保存在 native so 里），
 * 卡密、到期时间、设备占用等信息显示在卡片上。
 */
class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var store: TicketStore
    private var deviceId = ""

    private val pinnedX by lazy { RainCrypto.b64d(Config.pinnedX25519B64) }
    private val pinnedE by lazy { RainCrypto.b64d(Config.pinnedEd25519B64) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        store = TicketStore(this)
        deviceId = DeviceId.get(this)

        b.btnVerify.setOnClickListener { verify() }

        // 重启后若本地还存着未过期票据，直接恢复解锁状态
        store.load()?.let { s ->
            if (s.exp == null || s.exp > System.currentTimeMillis() / 1000) {
                // 简化演示：有票据即解锁，不重复走网络
                runCatching { RainGuard.nativeUnlock(ByteArray(0), true, true, s.exp ?: 0L) }
            }
        }
    }

    private fun verify() {
        val card = b.etCard.text?.toString()?.trim().orEmpty()
        if (card.isEmpty()) {
            Toast.makeText(this, "请输入卡密", Toast.LENGTH_SHORT).show()
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
                    showFail("握手失败", it.message ?: "未知错误")
                    return@launch
                }

                val r = client.verify(
                    card = card,
                    device = deviceId,
                    deviceName = DeviceId.model(),
                ).getOrElse {
                    showFail("网络错误", it.message ?: "未知错误")
                    return@launch
                }

                if (!r.ok) {
                    showFail("验证未通过", r.msg)
                    return@launch
                }

                // 解锁本地闸门
                val t = r.ticket
                if (t != null) {
                    store.save(t)
                    val (sigOk, _) = RainAuthClient.verifyTicketOffline(t, pinnedE)
                    runCatching {
                        RainGuard.nativeUnlock(
                            RainCrypto.ticketCanonical(t), sigOk, t.dev == deviceId, t.exp ?: 0L,
                        )
                    }
                }
                showOk(card, r)
            } finally {
                b.progress.visibility = View.GONE
                b.btnVerify.isEnabled = true
            }
        }
    }

    private fun showOk(card: String, r: VerifyResult) {
        b.card.setBackgroundColor(0xFFEBDCFF.toInt())
        b.tvStatus.text = if (RainGuard.nativeIsUnlocked()) "✓ 授权有效" else "授权有效"
        b.tvStatus.setTextColor(0xFF503C74.toInt())

        val exp = r.expireAt?.let { fmt(it) } ?: "永久有效"
        val remain = r.expireAt?.let { remain(it) } ?: "—"

        b.tvDetail.text = buildString {
            appendLine("卡　密   $card")
            appendLine("到期时间 $exp")
            appendLine("剩余时长 $remain")
            appendLine("设备占用 ${r.deviceUsed ?: "-"} / ${r.deviceMax ?: "-"}")
            appendLine("本机标识 $deviceId")
            appendLine("用户 ID  ${r.userId ?: "-"}")
            if (r.activatedNow) appendLine("状　态   本次为首次激活")
            appendLine("本地闸门 ${if (RainGuard.nativeIsUnlocked()) "已解锁" else "未解锁"}")
        }
        b.card.visibility = View.VISIBLE
    }

    private fun showFail(title: String, detail: String) {
        b.card.setBackgroundColor(0xFFFFDAD6.toInt())
        b.tvStatus.text = "✗ $title"
        b.tvStatus.setTextColor(0xFF93000A.toInt())
        b.tvDetail.text = detail
        b.card.visibility = View.VISIBLE
        runCatching { RainGuard.nativeLock() }
    }

    /** 把服务端返回的 RFC3339（可能带纳秒）转成本地时间显示 */
    private fun fmt(iso: String): String {
        return try {
            val m = Regex("""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""").find(iso)
            val t = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)
                .parse(m?.groupValues?.get(1) ?: iso)
            if (t == null) iso.take(16).replace("T", " ")
            else SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.CHINA).format(t)
        } catch (_: Exception) {
            iso.take(16).replace("T", " ")
        }
    }

    /** 剩余时长 */
    private fun remain(iso: String): String {
        return try {
            val m = Regex("""^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})""").find(iso)
            val end = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)
                .parse(m?.groupValues?.get(1) ?: iso)?.time
            if (end == null) "—"
            else {
                val ms = end - System.currentTimeMillis()
                if (ms <= 0) "已过期"
                else {
                    val d = ms / 86400000
                    val h = (ms % 86400000) / 3600000
                    if (d > 0) "$d 天 $h 小时" else "$h 小时"
                }
            }
        } catch (_: Exception) {
            "—"
        }
    }
}
