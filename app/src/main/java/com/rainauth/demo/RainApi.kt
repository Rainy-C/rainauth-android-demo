package com.rainauth.demo

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** 一条公告 */
data class Announce(
    val id: Long,
    val title: String,
    val content: String,
    val createdAt: String,
    val global: Boolean,
)

/** 版本检查结果 */
data class VersionInfo(
    val current: String,
    val latest: String?,
    val hasUpdate: Boolean,
    val downloadUrl: String?,
    val changelog: String?,
    val forceUpdate: Boolean,
)

/**
 * 无需会话的公开接口：公告与版本。
 *
 * 两者都用 app_key 定位应用，属于明文 HTTP 接口，不参与端到端加密 ——
 * 它们不含授权信息，只用于展示。
 */
object RainApi {

    private val http = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    suspend fun announcements(baseUrl: String, appKey: String): Result<List<Announce>> =
        withContext(Dispatchers.IO) {
            runCatching {
                val o = get("$baseUrl/client/announce?app_key=$appKey")
                val arr = o.optJSONArray("data") ?: JSONArray()
                (0 until arr.length()).map { i ->
                    val a = arr.getJSONObject(i)
                    Announce(
                        id = a.optLong("id"),
                        title = a.optString("title"),
                        content = a.optString("content"),
                        createdAt = a.optString("created_at"),
                        global = a.isNull("app_id"),
                    )
                }
            }
        }

    suspend fun version(
        baseUrl: String, appKey: String, current: String,
    ): Result<VersionInfo> = withContext(Dispatchers.IO) {
        runCatching {
            val o = get("$baseUrl/client/version?app_key=$appKey&version=$current")
            val d = o.optJSONObject("data") ?: o
            val latest = if (d.isNull("latest")) null else d.optJSONObject("latest")
            VersionInfo(
                current = d.optString("current", current),
                latest = latest?.optString("version"),
                hasUpdate = d.optBoolean("has_update", false),
                downloadUrl = latest?.optString("download_url")?.takeIf { it.isNotBlank() },
                changelog = latest?.optString("changelog")?.takeIf { it.isNotBlank() },
                forceUpdate = latest?.optBoolean("force_update", false) ?: false,
            )
        }
    }

    private fun get(url: String): JSONObject {
        val req = Request.Builder().url(url).get().build()
        http.newCall(req).execute().use { r ->
            val text = r.body?.string().orEmpty()
            if (text.isBlank()) throw Exception("HTTP ${r.code}：空响应")
            return JSONObject(text)
        }
    }
}

/**
 * JSON 美化器。
 *
 * 直接 `toString(2)` 会把 `ct` 那种几 KB 的 base64 整段铺出来，界面没法看。
 * 这里把过长字符串截断成 `前 48 字符…（共 N 字符）`，保留结构可读性。
 */
object JsonPretty {

    private const val MAX = 64

    fun format(raw: String): String = try {
        formatObj(JSONObject(raw), 0)
    } catch (_: Exception) {
        try {
            formatArr(JSONArray(raw), 0)
        } catch (_: Exception) {
            raw
        }
    }

    /** 供界面直接展示：解析失败就原样返回 */
    fun format(o: JSONObject): String = formatObj(o, 0)

    private fun formatObj(o: JSONObject, depth: Int): String {
        if (o.length() == 0) return "{}"
        val pad = "  ".repeat(depth + 1)
        val close = "  ".repeat(depth)
        val sb = StringBuilder("{\n")
        val keys = o.keys().asSequence().toList().sorted()
        keys.forEachIndexed { i, k ->
            sb.append(pad).append('"').append(k).append("\": ")
            sb.append(value(o.opt(k), depth + 1))
            if (i != keys.lastIndex) sb.append(',')
            sb.append('\n')
        }
        return sb.append(close).append('}').toString()
    }

    private fun formatArr(a: JSONArray, depth: Int): String {
        if (a.length() == 0) return "[]"
        val pad = "  ".repeat(depth + 1)
        val close = "  ".repeat(depth)
        val sb = StringBuilder("[\n")
        for (i in 0 until a.length()) {
            sb.append(pad).append(value(a.opt(i), depth + 1))
            if (i != a.length() - 1) sb.append(',')
            sb.append('\n')
        }
        return sb.append(close).append(']').toString()
    }

    private fun value(v: Any?, depth: Int): String = when (v) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> formatObj(v, depth)
        is JSONArray -> formatArr(v, depth)
        is String -> "\"" + shorten(v) + "\""
        else -> v.toString()
    }

    private fun shorten(s: String): String =
        if (s.length <= MAX) s else s.take(48) + "…（共 ${s.length} 字符）"
}
