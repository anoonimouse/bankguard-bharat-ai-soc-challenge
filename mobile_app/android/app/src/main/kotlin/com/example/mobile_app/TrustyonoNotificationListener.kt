package com.example.mobile_app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

class TrustyonoNotificationListener : NotificationListenerService() {
    private val notificationAction = "com.example.mobile_app.TRUSTYONO_NOTIFICATION"
    private val alertChannelId = "trustyono_alerts_native"
    private val engine = SocialEngineeringEngine()

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val extras = sbn.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        val combined = listOf(title, text, bigText)
            .filter { it.isNotBlank() }
            .joinToString(" \n")
            .trim()

        if (combined.isBlank()) {
            return
        }

        val pkg = sbn.packageName.lowercase()
        val isRelevant = pkg.contains("whatsapp") ||
            pkg.contains("telegram") ||
            pkg.contains("messaging") ||
            pkg.contains("mms")

        if (!isRelevant) return

        // --- Existing URL detection (unchanged) ---
        val hasUrl = containsUrl(combined)

        // --- New: Social Engineering Pattern Engine ---
        var analysisResult: SocialEngineeringEngine.AnalysisResult? = null
        try {
            analysisResult = engine.analyze(combined)
        } catch (_: Exception) {
            // Graceful fallback: if engine fails, continue with URL-only logic
        }

        // Determine final verdict: use engine result if available, else fall back to URL-only
        val finalVerdict: String
        val finalScore: Int
        val primaryCategory: String?
        val categories: List<String>

        if (analysisResult != null && analysisResult.verdict != "none") {
            finalVerdict = analysisResult.verdict
            finalScore = analysisResult.score
            primaryCategory = analysisResult.primaryCategory
            categories = analysisResult.categories
        } else if (hasUrl) {
            // Fallback: existing URL-only behavior (soft warning)
            finalVerdict = "soft"
            finalScore = 40
            primaryCategory = "url_only"
            categories = emptyList()
        } else {
            // Nothing detected, exit silently
            return
        }

        // Send enriched broadcast to Flutter
        val intent = Intent(notificationAction)
        intent.putExtra("package", sbn.packageName)
        intent.putExtra("text", combined)
        intent.putExtra("score", finalScore)
        intent.putExtra("verdict", finalVerdict)
        intent.putExtra("primaryCategory", primaryCategory ?: "")
        intent.putStringArrayListExtra("categories", ArrayList(categories))
        sendBroadcast(intent)

        // Show contextual system notification
        val (alertTitle, alertBody) = getContextualMessage(primaryCategory)
        showLocalAlert(alertTitle, alertBody)
    }

    private fun getContextualMessage(primaryCategory: String?): Pair<String, String> {
        return when (primaryCategory) {
            "urgency" -> Pair(
                "[ALERT] Fraud Urgency Tactic Detected",
                "This message is creating false urgency. SBI never threatens to block accounts or expire KYC via SMS or WhatsApp."
            )
            "fear" -> Pair(
                "[ALERT] Known Fraud Script Detected",
                "This message is using a known banking fraud pattern. Your account is not compromised. Do not click any links."
            )
            "greed" -> Pair(
                "[ALERT] Fake Reward Scam Detected",
                "This message is offering fake rewards to steal your credentials. SBI does not send prize notifications via WhatsApp or SMS."
            )
            "url_only" -> Pair(
                "[ALERT] Suspicious Banking Link Detected",
                "A link related to SBI was found in a message. Verify it before clicking."
            )
            else -> Pair(
                "[ALERT] Suspicious Link Detected",
                "A potentially malicious link was found in a message notification."
            )
        }
    }

    private fun containsUrl(text: String): Boolean {
        val regex = Regex("(https?:\\/\\/[^\\s]+)", RegexOption.IGNORE_CASE)
        return regex.containsMatchIn(text)
    }

    private fun showLocalAlert(title: String, body: String) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                alertChannelId,
                "TrustYONO Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            manager.createNotificationChannel(channel)
        }

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = Notification.Builder(this, alertChannelId)
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        manager.notify(1001, notification)
    }
}
