package com.bankguard.sdk

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.database.ContentObserver
import java.util.Collections
import java.util.HashSet
import kotlin.math.abs
import org.json.JSONArray
import org.json.JSONObject

/**
 * SDK-level Notification Listener Service.
 * Intercepts notifications from messaging apps, runs the SocialEngineeringEngine,
 * and broadcasts enriched threat data to the host app via a dynamic action string.
 *
 * Now includes:
 * - Unique notification IDs per alert (hash-based, no ID collisions)
 * - "Check Link" and "Report Scam" action buttons via bankguard:// deep links
 */
class BankguardNotificationListenerService : NotificationListenerService() {
    private val alertChannelId = "bankguard_alerts"
    private val engine = SocialEngineeringEngine()
    private var apkFileObserver: ApkFileObserver? = null
    private val processedSmsIds = Collections.synchronizedSet(HashSet<Long>())
    private val processedMessageHashes = Collections.synchronizedSet(HashSet<String>())
    private var smsObserver: ContentObserver? = null

    private lateinit var localTextAnalyzer: LocalPhishingTextAnalyzer

    override fun onCreate() {
        super.onCreate()
        localTextAnalyzer = LocalPhishingTextAnalyzer(this)
        
        android.util.Log.i("BANKGUARD_PLUGIN", "Service onCreate - starting ApkFileObserver background listener")
        apkFileObserver = ApkFileObserver(this) { info ->
            try {
                val broadcastIntent = Intent("$packageName.BANKGUARD_FILE_ALERT").apply {
                    setPackage(packageName)
                    putExtra("id", info.id)
                    putExtra("displayName", info.displayName)
                    putExtra("filePath", info.filePath)
                    putExtra("fileSize", info.fileSize)
                    putExtra("dateAdded", info.dateAdded)
                    putExtra("mimeType", info.mimeType)
                    putExtra("sourceDirectory", info.sourceDirectory)
                    putExtra("isFromWatchedDir", info.isFromWatchedDir)
                }
                sendBroadcast(broadcastIntent)
                android.util.Log.i("BANKGUARD_PLUGIN", "Broadcasted file alert event for ${info.displayName}")
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_PLUGIN", "Failed to broadcast file alert: ${e.message}")
            }
        }
        apkFileObserver?.start()

        registerSmsObserver()
        checkLatestUnreadSms()
    }

    override fun onDestroy() {
        apkFileObserver?.stop()
        unregisterSmsObserver()
        android.util.Log.i("BANKGUARD_PLUGIN", "Service onDestroy - stopped ApkFileObserver background listener")
        super.onDestroy()
    }

    private fun getBroadcastAction(): String {
        return "$packageName.BANKGUARD_NOTIFICATION"
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        android.util.Log.e("BANKGUARD_PLUGIN", "onNotificationPosted from ${sbn.packageName}")
        val extras = sbn.notification.extras
        val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
        val text = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() ?: ""
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString() ?: ""

        val messagesList = mutableListOf<String>()
        if (text.isNotBlank()) messagesList.add(text)
        if (bigText.isNotBlank() && bigText != text) messagesList.add(bigText)

        // Extract MessagingStyle messages (e.g. WhatsApp, Telegram conversations)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val messages = extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            if (messages != null) {
                for (msgObj in messages) {
                    if (msgObj is Bundle) {
                        val textVal = msgObj.getCharSequence("text")?.toString()
                        if (!textVal.isNullOrBlank()) {
                            messagesList.add(textVal)
                        }
                    }
                }
            }
        }

        // Extract InboxStyle text lines
        val textLines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)
        if (textLines != null) {
            for (line in textLines) {
                if (!line.isNullOrBlank()) {
                    messagesList.add(line.toString())
                }
            }
        }

        val combined = (listOf(title) + messagesList)
            .filter { it.isNotBlank() }
            .distinct()
            .joinToString(" \n")
            .trim()

        if (combined.isBlank()) {
            android.util.Log.e("BANKGUARD_PLUGIN", "Notification content is blank, ignoring")
            return
        }

        processIncomingMessageText(sbn.packageName, title, combined)
    }

    private fun isDuplicateMessage(text: String): Boolean {
        val clean = text.trim().lowercase()
        if (processedMessageHashes.contains(clean)) return true
        processedMessageHashes.add(clean)
        if (processedMessageHashes.size > 200) {
            processedMessageHashes.clear()
            processedMessageHashes.add(clean)
        }
        return false
    }

    private fun registerSmsObserver() {
        val smsUri = Uri.parse("content://sms")
        smsObserver = object : ContentObserver(android.os.Handler(android.os.Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                super.onChange(selfChange)
                android.util.Log.i("BANKGUARD_PLUGIN", "SMS ContentObserver onChange triggered")
                checkLatestUnreadSms()
            }
        }
        try {
            contentResolver.registerContentObserver(smsUri, true, smsObserver!!)
            android.util.Log.i("BANKGUARD_PLUGIN", "Successfully registered SMS content observer")
        } catch (e: Exception) {
            android.util.Log.e("BANKGUARD_PLUGIN", "Failed to register SMS content observer: ${e.message}")
        }
    }

    private fun unregisterSmsObserver() {
        smsObserver?.let {
            try {
                contentResolver.unregisterContentObserver(it)
                android.util.Log.i("BANKGUARD_PLUGIN", "Unregistered SMS content observer")
            } catch (_: Exception) {}
            smsObserver = null
        }
    }

    private fun checkLatestUnreadSms() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (checkSelfPermission(android.Manifest.permission.READ_SMS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                android.util.Log.w("BANKGUARD_PLUGIN", "No READ_SMS permission, skipping checkLatestUnreadSms")
                return
            }
        }

        Thread {
            try {
                val uri = Uri.parse("content://sms/inbox")
                val cursor = contentResolver.query(
                    uri,
                    arrayOf("_id", "address", "body", "date", "read"),
                    null,
                    null,
                    "date DESC LIMIT 1"
                )

                cursor?.use { c ->
                    if (c.moveToFirst()) {
                        val id = c.getLong(c.getColumnIndexOrThrow("_id"))
                        val address = c.getString(c.getColumnIndexOrThrow("address")) ?: ""
                        val body = c.getString(c.getColumnIndexOrThrow("body")) ?: ""
                        val date = c.getLong(c.getColumnIndexOrThrow("date"))

                        // Ignore historical messages older than 30 seconds to avoid retroactive triggers on boot
                        if (System.currentTimeMillis() - date > 30000) {
                            return@Thread
                        }

                        if (processedSmsIds.contains(id)) {
                            return@Thread
                        }
                        processedSmsIds.add(id)

                        if (processedSmsIds.size > 200) {
                            processedSmsIds.clear()
                            processedSmsIds.add(id)
                        }

                        android.util.Log.i("BANKGUARD_PLUGIN", "New SMS detected (id: $id, from: $address)")
                        processIncomingMessageText("com.android.mms", address, body)
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_PLUGIN", "Error querying latest unread SMS: ${e.message}")
            }
        }.start()
    }

    private fun processIncomingMessageText(pkg: String, title: String, combined: String) {
        val cleanPkg = pkg.lowercase()
        val isRelevant = cleanPkg.contains("whatsapp") ||
            cleanPkg.contains("telegram") ||
            cleanPkg.contains("messaging") ||
            cleanPkg.contains("mms")

        if (!isRelevant) {
            android.util.Log.e("BANKGUARD_PLUGIN", "Package $cleanPkg not relevant, ignoring")
            return
        }

        if (isDuplicateMessage(combined)) {
            android.util.Log.i("BANKGUARD_PLUGIN", "Deduplicating duplicate message analysis call")
            return
        }

        android.util.Log.e("BANKGUARD_PLUGIN", "Analyzing notification/SMS: $combined")

        // --- SENDER VERIFICATION RULES ---
        val isSms = cleanPkg.contains("messaging") || cleanPkg.contains("mms")
        val isWhatsApp = cleanPkg.contains("whatsapp") || cleanPkg.contains("telegram")
        var senderFlag = ""
        var senderPenalty = 0

        val cleanTitle = title.replace("+", "").replace(" ", "").replace("-", "").trim().uppercase()
        val isMobileNumber = cleanTitle.matches(Regex("^[0-9]{10,13}$"))
        val mentionsBank = ScamTriggers.bankAppKeywords.any { combined.lowercase().contains(it) }

        if (mentionsBank) {
            if (isSms) {
                if (isMobileNumber) {
                    senderPenalty = 45
                    senderFlag = "Suspicious SMS: Personal mobile number used for official Bank alert"
                } else {
                    val officialHeaders = setOf(
                        "SBIUPI", "SBIBNK", "ATMSBI", "CBSSBI", "SBICRD",
                        "HDFCBK", "HDFCUPI", "HDFCAF", "HDFCCC",
                        "ICICIB", "ICICIUPI", "ICICICC",
                        "AXISBK", "AXISUPI", "AXISCC",
                        "PAYTM", "PYTMBK",
                        "AUBANK", "AUBKUP",
                        "NPCINP", "BHAMIM"
                    )
                    val isOfficialHeader = officialHeaders.any { cleanTitle.endsWith(it) }
                    if (!isOfficialHeader) {
                        val usesLookalikeKeyword = listOf("SBI", "YONO", "HDFC", "ICICI", "AXIS", "PAYTM")
                            .any { cleanTitle.contains(it) }
                        if (usesLookalikeKeyword) {
                            senderPenalty = 40
                            senderFlag = "Suspicious SMS: Unverified spoofed/lookalike Bank sender ID"
                        }
                    } else {
                        senderFlag = "Verified Official Bank SMS Header"
                    }
                }
            } else if (isWhatsApp) {
                senderPenalty = 45
                senderFlag = "Suspicious WhatsApp: Unverified personal account used for Bank alert"
            }
        }

        val hasUrl = containsUrl(combined)
        val localAnalysis = try {
            localTextAnalyzer.analyze(combined)
        } catch (_: Exception) {
            null
        }

        var analysisResult: SocialEngineeringEngine.AnalysisResult? = null
        try {
            analysisResult = engine.analyze(combined)
        } catch (_: Exception) {
            // Graceful fallback
        }

        val localVerdict = when {
            localAnalysis == null -> "none"
            localAnalysis.phishingConfidence >= 0.85 -> "hard"
            localAnalysis.phishingConfidence >= 0.50 -> "soft"
            else -> "none"
        }

        var finalVerdict: String
        var finalScore: Int
        var primaryCategory: String?
        var categories: List<String>

        var engineScore = analysisResult?.score ?: 0
        val localScore = ((localAnalysis?.phishingConfidence ?: 0.0) * 100).toInt()

        if (senderPenalty > 0 && (engineScore > 0 || localScore > 0 || hasUrl)) {
            engineScore = (engineScore + senderPenalty).coerceAtMost(100)
        }

        if ((analysisResult != null && analysisResult.verdict != "none") || localVerdict != "none") {
            finalScore = maxOf(engineScore, localScore)
            finalVerdict = when {
                finalScore >= 70 || analysisResult?.verdict == "hard" || localVerdict == "hard" -> "hard"
                finalScore >= 35 || analysisResult?.verdict == "soft" || localVerdict == "soft" -> "soft"
                else -> "none"
            }
            primaryCategory = analysisResult?.primaryCategory ?: if (localScore > 0) "local_nlp" else null
            categories = (analysisResult?.categories ?: emptyList()).toMutableList().apply {
                if (senderFlag.isNotEmpty() && !contains("suspicious_sender")) {
                    add("suspicious_sender")
                }
            }
        } else if (hasUrl) {
            finalScore = maxOf(40 + senderPenalty, 40).coerceAtMost(100)
            finalVerdict = if (finalScore >= 70) "hard" else "soft"
            primaryCategory = "url_only"
            categories = if (senderFlag.isNotEmpty()) listOf("suspicious_sender") else emptyList()
        } else {
            android.util.Log.e("BANKGUARD_PLUGIN", "No threat detected and no URL, ignoring")
            return
        }

        android.util.Log.e("BANKGUARD_PLUGIN", "Sending broadcast for verdict: $finalVerdict, score: $finalScore, sender: $title")
        val eventData = mapOf(
            "package" to pkg,
            "sender" to title,
            "senderFlag" to senderFlag,
            "text" to combined,
            "score" to finalScore,
            "verdict" to finalVerdict,
            "primaryCategory" to (primaryCategory ?: ""),
            "categories" to categories,
            "localNlpConfidence" to (localAnalysis?.phishingConfidence ?: 0.0),
            "localNlpVerdict" to localVerdict,
            "localNlpModel" to (localAnalysis?.modelName ?: "mrm8488/bert-tiny-finetuned-sms-spam-detection"),
            "localNlpIndicators" to (localAnalysis?.indicators?.map { indicator ->
                mapOf(
                    "name" to indicator.name,
                    "detected" to indicator.detected,
                    "evidence" to (indicator.evidence ?: "")
                )
            } ?: emptyList<Map<String, Any>>())
        )
        BankguardPlugin.pendingNotificationEvent = eventData
        
        val intent = Intent(getBroadcastAction())
        intent.setPackage(packageName)
        intent.putExtra("package", pkg)
        intent.putExtra("sender", title)
        intent.putExtra("senderFlag", senderFlag)
        intent.putExtra("text", combined)
        intent.putExtra("score", finalScore)
        intent.putExtra("verdict", finalVerdict)
        intent.putExtra("primaryCategory", primaryCategory ?: "")
        intent.putStringArrayListExtra("categories", ArrayList(categories))
        intent.putExtra("localNlpConfidence", localAnalysis?.phishingConfidence ?: 0.0)
        intent.putExtra("localNlpVerdict", localVerdict)
        intent.putExtra("localNlpModel", localAnalysis?.modelName ?: "mrm8488/bert-tiny-finetuned-sms-spam-detection")
        intent.putExtra("localNlpIndicatorsJson", buildIndicatorsJson(localAnalysis?.indicators ?: emptyList()))
        sendBroadcast(intent)
        android.util.Log.e("BANKGUARD_PLUGIN", "Broadcast sent explicitly to $packageName with action ${getBroadcastAction()}")

        // Show the lightweight Floating Security Badge overlay if permission is granted
        try {
            val badge = FloatingSecurityBadge.getInstance(this)
            if (badge.hasOverlayPermission()) {
                badge.show(finalVerdict, combined)
                android.util.Log.i("BANKGUARD_PLUGIN", "Floating security badge displayed")
            } else {
                android.util.Log.w("BANKGUARD_PLUGIN", "Overlay permission not granted; skipped floating badge")
            }
        } catch (e: Exception) {
            android.util.Log.e("BANKGUARD_PLUGIN", "Failed to display floating badge: ${e.message}")
        }

        // Extract URL for action buttons and pre-fetch safety status
        val detectedUrl = extractFirstUrl(combined)
        if (detectedUrl != null) {
            prefetchUrlSafety(detectedUrl)
        }

        val (alertTitle, alertBody) = getContextualMessage(primaryCategory)
        showLocalAlert(
            alertTitle,
            alertBody,
            combined,
            detectedUrl,
            primaryCategory ?: "",
            analysisResult?.isHighSeverity ?: false
        )
    }

    private fun prefetchUrlSafety(urlStr: String) {
        // Run fast local heuristics first
        val localScanner = UrlHeuristicScanner()
        val localResult = localScanner.scan(urlStr)
        if (localResult.verdict == "hard") {
            UrlThreatCache.put(urlStr, false)
            android.util.Log.i("BG_NotifListener", "Prefetched URL local verdict: UNSAFE: $urlStr")
            return
        }
        if (localResult.isSafe && localResult.score == 0) {
            UrlThreatCache.put(urlStr, true)
            android.util.Log.i("BG_NotifListener", "Prefetched URL local whitelist: SAFE: $urlStr")
            return
        }

        // Otherwise query backend database asynchronously
        kotlin.concurrent.thread {
            try {
                val prefs = getSharedPreferences("bankguard_prefs", Context.MODE_PRIVATE)
                val backendBaseUrl = prefs.getString("backendBaseUrl", "https://api.doy.codes") ?: "https://api.doy.codes"
                val cleanBase = if (backendBaseUrl.endsWith("/")) backendBaseUrl.substring(0, backendBaseUrl.length - 1) else backendBaseUrl

                val apiEndpoint = java.net.URL("$cleanBase/api/check-url")
                val connection = apiEndpoint.openConnection() as java.net.HttpURLConnection
                connection.requestMethod = "POST"
                connection.connectTimeout = 1500
                connection.readTimeout = 1500
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setRequestProperty("Accept", "application/json")

                val jsonPayload = "{\"url\":\"$urlStr\"}"
                connection.outputStream.use { os ->
                    os.write(jsonPayload.toByteArray(Charsets.UTF_8))
                }

                val code = connection.responseCode
                if (code == 200) {
                    val response = connection.inputStream.bufferedReader().use { it.readText() }
                    var isSafe = true
                    if (response.contains("\"is_safe\":false") || response.contains("\"is_safe\": false")) {
                        isSafe = false
                    }
                    UrlThreatCache.put(urlStr, isSafe)
                    android.util.Log.i("BG_NotifListener", "Prefetched URL backend verdict cached ($isSafe): $urlStr")
                } else {
                    UrlThreatCache.put(urlStr, localResult.isSafe)
                    android.util.Log.w("BG_NotifListener", "Prefetch backend error code $code, using local safety: ${localResult.isSafe}")
                }
                connection.disconnect()
            } catch (e: Exception) {
                UrlThreatCache.put(urlStr, localResult.isSafe)
                android.util.Log.e("BG_NotifListener", "Prefetch failed, using local safety: ${localResult.isSafe}. Error: ${e.message}")
            }
        }
    }

    private fun getContextualMessage(primaryCategory: String?): Pair<String, String> {
        return when (primaryCategory) {
            "apk_distribution" -> Pair(
                "CRITICAL: Fake App Distribution Detected",
                "WARNING: This message is trying to make you install a FAKE banking app. NEVER download APK files from links. Install YONO only from the Google Play Store."
            )
            "urgency" -> Pair(
                "[ALERT] Fraud Urgency Tactic Detected",
                "This message is creating false urgency. Banks never threaten to block accounts or expire KYC via SMS or WhatsApp."
            )
            "fear" -> Pair(
                "[ALERT] Known Fraud Script Detected",
                "This message is using a known banking fraud pattern. Your account is not compromised. Do not click any links."
            )
            "authority" -> Pair(
                "CRITICAL: Digital Arrest Scam Detected",
                "WARNING: This message impersonates Law Enforcement (Police/CBI). 'Digital Arrest' is NOT a legal procedure. Do NOT join any video calls or transfer money."
            )
            "utility" -> Pair(
                "[ALERT] Electricity Bill Scam Detected",
                "WARNING: Scammers are threatening to cut your power at 9:30 PM. This is a FAKE message. Official utilities never send disconnection threats via WhatsApp/SMS."
            )
            "challan" -> Pair(
                "CRITICAL: Traffic Challan Scam Detected",
                "WARNING: This e-Challan alert is likely fake. Real police do not threaten immediate license suspension via SMS links. Check parivahan.gov.in directly."
            )
            "migration" -> Pair(
                "[ALERT] Bank Domain Migration Alert",
                "A message about '.bank.in' migration was detected. While banks are migrating, they will NEVER ask for OTPs or passwords via SMS links to complete the process."
            )
            "scheme" -> Pair(
                "[ALERT] Govt Scheme Scam Detected",
                "WARNING: This message about PM-Kisan / Govt subsidies is likely a scam to steal Your Aadhaar or bank details. Verify via official portals only."
            )
            "opportunity" -> Pair(
                "[ALERT] Part-Time Job Scam Detected",
                "This job offer for 'liking videos' or 'simple tasks' is a known scam to steal your data and money."
            )
            "greed" -> Pair(
                "[ALERT] Fake Reward Scam Detected",
                "This message is offering fake rewards to steal your credentials. Banks do not send prize notifications via WhatsApp or SMS."
            )
            "remote_access" -> Pair(
                "CRITICAL: Remote Access Scam Detected",
                "WARNING: This message asks you to download remote support tools (AnyDesk/TeamViewer) or share your screen. NEVER share your screen, IDs, or codes with callers."
            )
            "otp_request" -> Pair(
                "CRITICAL: OTP Request Scam Detected",
                "WARNING: This message is requesting you to tell, send, or share an OTP. Banks never ask for OTPs via text. NEVER share OTPs to verify or process refunds."
            )
            "phone_only" -> Pair(
                "[ALERT] Callback Scam Number Detected",
                "A suspicious telephone callback number was found in a message. Scammers use fake toll-free numbers to trick you. Do not call this number."
            )
            "url_only" -> Pair(
                "[ALERT] Suspicious Banking Link Detected",
                "A link related to banking was found in a message. Verify it before clicking."
            )
            else -> Pair(
                "[ALERT] Suspicious Link Detected",
                "A potentially malicious link was found in a message notification."
            )
        }
    }

    private fun containsUrl(text: String): Boolean {
        val lower = text.lowercase()
        val standardRegex = Regex("(https?:\\/\\/[^\\s]+)", RegexOption.IGNORE_CASE)
        if (standardRegex.containsMatchIn(text)) return true

        // Obfuscated URL checks (spaces, asterisks)
        val obfuscatedPatterns = listOf(
            "http ://", "https ://", "http: //", "https: //", "http : / /", "https : / /",
            "h t t p :", "h t t p s :", "w w w ."
        )
        if (obfuscatedPatterns.any { lower.contains(it) }) return true

        val domainRegex = Regex("[a-z0-9\\-]+?\\s*\\.\\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co)\\b")
        return domainRegex.containsMatchIn(lower)
    }

    private fun extractFirstUrl(text: String): String? {
        val standardRegex = Regex("(https?:\\/\\/[^\\s]+)", RegexOption.IGNORE_CASE)
        val match = standardRegex.find(text)?.groupValues?.getOrNull(0)
        if (match != null) return match

        // Reconstruct obfuscated URL if found
        val domainRegex = Regex("([a-z0-9\\-]+?\\s*\\.\\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co))\\b", RegexOption.IGNORE_CASE)
        val domainMatch = domainRegex.find(text.lowercase())?.groupValues?.getOrNull(1)
        if (domainMatch != null) {
            val cleanedDomain = domainMatch.replace(" ", "")
            return "http://$cleanedDomain"
        }
        return null
    }

    private fun buildIndicatorsJson(indicators: List<PhishingTextAnalyzer.Indicator>): String {
        val array = JSONArray()
        for (indicator in indicators) {
            val item = JSONObject()
            item.put("name", indicator.name)
            item.put("detected", indicator.detected)
            item.put("evidence", indicator.evidence ?: "")
            array.put(item)
        }
        return array.toString()
    }

    /** Generate a unique, stable notification ID from the content. */
    private fun generateNotificationId(text: String): Int {
        return abs(("$text${System.currentTimeMillis()}").hashCode()) % 100000 + 2000
    }

    private fun showLocalAlert(
        title: String,
        body: String,
        originalText: String,
        detectedUrl: String?,
        primaryCategory: String,
        isHighSeverity: Boolean
    ) {
        val manager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                alertChannelId,
                "Bankguard Security Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            manager.createNotificationChannel(channel)
        }

        // Main tap: open the host app
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val mainPendingIntent = PendingIntent.getActivity(
            this, 0, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notificationId = generateNotificationId(originalText)
        val builder = Notification.Builder(this, alertChannelId)
            .setSmallIcon(if (isHighSeverity) android.R.drawable.ic_dialog_alert else android.R.drawable.stat_notify_error)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(Notification.BigTextStyle().bigText(body))
            .setContentIntent(mainPendingIntent)
            .setAutoCancel(true)

        if (isHighSeverity) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setPriority(Notification.PRIORITY_MAX)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                builder.setVisibility(Notification.VISIBILITY_PUBLIC)
            }
        }

        // Action 1: "Check Link" - only if we have a URL
        if (detectedUrl != null) {
            val verifyUri = Uri.parse("bankguard://verify?url=${Uri.encode(detectedUrl)}")
            val verifyIntent = Intent(Intent.ACTION_VIEW, verifyUri).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                `package` = packageName
            }
            val verifyPendingIntent = PendingIntent.getActivity(
                this, notificationId + 1, verifyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(
                Notification.Action.Builder(
                    null, "Check Link", verifyPendingIntent
                ).build()
            )
        }

        // Action 2: "Report Scam" - always shown
        val encodedUrl = if (detectedUrl != null) Uri.encode(detectedUrl) else ""
        val reportUri = Uri.parse(
            "bankguard://report?url=$encodedUrl&source=notification&category=${Uri.encode(primaryCategory)}"
        )
        val reportIntent = Intent(Intent.ACTION_VIEW, reportUri).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            `package` = packageName
        }
        val reportPendingIntent = PendingIntent.getActivity(
            this, notificationId + 2, reportIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        builder.addAction(
            Notification.Action.Builder(
                null, "Report Scam", reportPendingIntent
            ).build()
        )

        manager.notify(notificationId, builder.build())
    }
}
