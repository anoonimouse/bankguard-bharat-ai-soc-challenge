package com.bankguard.sdk

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

/**
 * Gate Activity that intercepts http/https intent links system-wide.
 * Displays a soft, minimal loader, verifies the URL asynchronously, and forwards the intent.
 */
class BankGuardGateActivity : Activity() {

    companion object {
        private const val TAG = "BG_GateActivity"
    }

    private var targetUrl: String? = null
    private val localScanner = UrlHeuristicScanner()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Extract Target URL from View Intent
        val intentData = intent.data
        if (intentData == null) {
            Log.e(TAG, "No intent data found, finishing")
            finish()
            return
        }

        val urlString = intentData.toString()
        targetUrl = urlString
        Log.i(TAG, "Intercepted link validation request: $urlString")

        // 2. Perform INSTANT Cache & Local Whitelist checks (Zero UI latency for safe paths)
        val cachedSafe = UrlThreatCache.get(urlString)
        if (cachedSafe != null) {
            Log.i(TAG, "Cache HIT: URL found in UrlThreatCache (isSafe = $cachedSafe), routing instantly: $urlString")
            if (cachedSafe) {
                forwardToBrowser(urlString)
            } else {
                triggerBlockPage(urlString)
            }
            return
        }

        val localResult = localScanner.scan(urlString)
        if (localResult.isSafe && localResult.score == 0) {
            Log.i(TAG, "Local whitelist HIT: routing instantly: $urlString")
            forwardToBrowser(urlString)
            return
        }
        if (localResult.verdict == "hard") {
            Log.w(TAG, "Local blacklist HIT: blocking instantly: $urlString")
            triggerBlockPage(urlString)
            return
        }

        // 3. Cache Miss: Setup Soft Minimal Branded Loader UI
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(0xFF0F172A.toInt()) // Soft slate 900 background
            layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT
            )
        }

        val spinner = ProgressBar(this).apply {
            isIndeterminate = true
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                indeterminateTintList = android.content.res.ColorStateList.valueOf(0xFF00FFCC.toInt()) // BankGuard Green accent
            }
            layoutParams = LinearLayout.LayoutParams(100, 100)
        }

        val statusLabel = TextView(this).apply {
            text = "BankGuard is verifying this link..."
            setTextColor(0xFFE2E8F0.toInt()) // slate-200
            textSize = 14f
            gravity = Gravity.CENTER
            setPadding(32, 24, 32, 0)
        }

        container.addView(spinner)
        container.addView(statusLabel)
        setContentView(container)

        // 4. Asynchronous Verification
        thread {
            verifyAndRoute(urlString, localResult)
        }
    }

    private fun verifyAndRoute(urlStr: String, localResult: UrlHeuristicScanner.ScanResult) {
        try {
            // Step B: Query Backend Threat Database (Already verified cache & local whitelist misses in onCreate)
            val prefs = getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
            val backendBaseUrl = prefs.getString("backendBaseUrl", "https://api.doy.codes") ?: "https://api.doy.codes"
            val cleanBase = if (backendBaseUrl.endsWith("/")) backendBaseUrl.substring(0, backendBaseUrl.length - 1) else backendBaseUrl

            var isSafe = true
            var connection: HttpURLConnection? = null
            try {
                val apiEndpoint = URL("$cleanBase/api/check-url")
                connection = apiEndpoint.openConnection() as HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 800
                connection.readTimeout = 800
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Accept", "application/json")

                val jsonPayload = "{\"url\":\"$urlStr\"}"
                connection.outputStream.use { os ->
                    os.write(jsonPayload.toByteArray(Charsets.UTF_8))
                }

                val code = connection.responseCode
                if (code == 200) {
                    val response = connection.inputStream.bufferedReader().use(BufferedReader::readText)
                    Log.i(TAG, "Backend URL check response: $response")
                    if (response.contains("\"is_safe\":false") || response.contains("\"is_safe\": false")) {
                        isSafe = false
                    }
                } else {
                    Log.w(TAG, "Backend returned error code $code, falling back to local heuristics")
                    isSafe = localResult.isSafe
                }
            } catch (e: Exception) {
                Log.e(TAG, "Network lookup failed, falling back to local heuristics: ${e.message}")
                isSafe = localResult.isSafe
            } finally {
                connection?.disconnect()
            }

            // Cache the result pre-emptively for future requests
            UrlThreatCache.put(urlStr, isSafe)

            // Step C: Route according to decision
            if (isSafe) {
                Log.i(TAG, "URL cleared: routing traffic to browser: $urlStr")
                forwardToBrowser(urlStr)
            } else {
                Log.w(TAG, "URL flagged as threat: blocking link launch: $urlStr")
                triggerBlockPage(urlStr)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error in validation pipeline, failing open for safety: ${e.message}")
            forwardToBrowser(urlStr)
        }
    }

    private fun triggerBlockPage(urlStr: String) {
        runOnUiThread {
            val intent = Intent(this, BlockPageActivity::class.java).apply {
                putExtra("url", urlStr)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            startActivity(intent)
            finish()
        }
    }

    private fun forwardToBrowser(urlStr: String) {
        runOnUiThread {
            val targetIntent = Intent(Intent.ACTION_VIEW, Uri.parse(urlStr)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }

            val pm = packageManager
            val resolveInfos = pm.queryIntentActivities(targetIntent, PackageManager.MATCH_DEFAULT_ONLY)
            var resolved = false

            for (info in resolveInfos) {
                val pkg = info.activityInfo.packageName
                if (pkg != packageName) {
                    targetIntent.setPackage(pkg)
                    startActivity(targetIntent)
                    resolved = true
                    break
                }
            }

            // Hard fallback if standard resolution yields empty results (common on Android 11+ Package Visibility)
            if (!resolved) {
                try {
                    // Force target to Google Chrome
                    targetIntent.setPackage("com.android.chrome")
                    startActivity(targetIntent)
                    resolved = true
                } catch (e: Exception) {
                    // Fall back to system chooser
                    targetIntent.setPackage(null)
                    val chooser = Intent.createChooser(targetIntent, "Open with")
                    chooser.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    startActivity(chooser)
                }
            }
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
    }
}
