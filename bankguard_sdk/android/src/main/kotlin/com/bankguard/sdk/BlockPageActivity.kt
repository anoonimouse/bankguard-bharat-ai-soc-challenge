package com.bankguard.sdk

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import java.util.Locale

/**
 * Native Activity containing a Webview to render the offline block warning page.
 * Bridges Text-to-Speech requests to the native Android TTS engine for 100% playback reliability.
 */
class BlockPageActivity : Activity(), TextToSpeech.OnInitListener {

    private lateinit var webView: WebView
    private var tts: TextToSpeech? = null
    private var isTtsReady = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 1. Initialize Native Text-To-Speech engine
        tts = TextToSpeech(this, this)

        // 2. Programmatically instantiate WebView
        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.allowFileAccess = true
            settings.mediaPlaybackRequiresUserGesture = false

            // Register public bridge to allow JS to invoke native activity finishes and TTS operations
            addJavascriptInterface(WebAppInterface(), "AndroidBridge")

            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    val prefs = getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
                    val activeLanguage = prefs.getString("language", "en") ?: "en"
                    evaluateJavascript("render('$activeLanguage');", null)
                    evaluateJavascript("try { speak('$activeLanguage'); } catch(_) {}", null)
                }
            }
        }

        setContentView(webView)
        webView.loadUrl("file:///android_asset/block_page.html")
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            isTtsReady = true
            tts?.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) {
                    // Handled
                }

                override fun onDone(utteranceId: String?) {
                    runOnUiThread {
                        webView.evaluateJavascript("setSpeakingState(false); isSpeaking = false;", null)
                    }
                }

                override fun onError(utteranceId: String?) {
                    runOnUiThread {
                        webView.evaluateJavascript("setSpeakingState(false); isSpeaking = false;", null)
                    }
                }
            })
            runOnUiThread {
                webView.evaluateJavascript("try { speak(currentLang); } catch(_) {}", null)
            }
        } else {
            Log.e("BG_BlockPageActivity", "Failed to initialize native TTS engine")
        }
    }

    private fun nativeSpeak(text: String, langCode: String) {
        if (!isTtsReady || tts == null) return
        val locale = when (langCode.lowercase()) {
            "hi" -> Locale("hi", "IN")
            "ta" -> Locale("ta", "IN")
            "te" -> Locale("te", "IN")
            "bn" -> Locale("bn", "IN")
            "mr" -> Locale("mr", "IN")
            else -> Locale.ENGLISH
        }
        try {
            tts?.language = locale
            val params = Bundle().apply {
                putString(TextToSpeech.Engine.KEY_PARAM_UTTERANCE_ID, "BG_WEB_TTS")
            }
            tts?.speak(text, TextToSpeech.QUEUE_FLUSH, params, "BG_WEB_TTS")
        } catch (e: Exception) {
            Log.e("BG_BlockPageActivity", "TTS native speak failed: ${e.message}")
        }
    }

    private fun nativeCancel() {
        try {
            tts?.stop()
        } catch (_: Exception) {}
    }

    override fun onDestroy() {
        try {
            tts?.stop()
            tts?.shutdown()
        } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onBackPressed() {
        super.onBackPressed()
        finish()
    }

    inner class WebAppInterface {
        @JavascriptInterface
        fun closePage() {
            runOnUiThread {
                finish()
            }
        }

        @JavascriptInterface
        fun speakText(text: String, lang: String) {
            runOnUiThread {
                nativeSpeak(text, lang)
            }
        }

        @JavascriptInterface
        fun cancelSpeak() {
            runOnUiThread {
                nativeCancel()
            }
        }
    }
}
