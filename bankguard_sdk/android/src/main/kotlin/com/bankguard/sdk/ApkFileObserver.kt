package com.bankguard.sdk

import android.content.ContentResolver
import android.content.Context
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent

/**
 * Layer 2B: APK File Observer for filesystem-level APK detection.
 *
 * Monitors the device's media store for new APK files appearing
 * in common directories (Downloads, WhatsApp Media, Telegram, etc.).
 *
 * Android 11+ Strategy:
 *   Direct FileObserver on /sdcard paths is unreliable due to scoped storage.
 *   Instead, we use a ContentObserver on MediaStore to detect new media entries
 *   with APK MIME type or .apk extension. This approach works across all OEMs
 *   without requiring MANAGE_EXTERNAL_STORAGE.
 *
 * Pre-Android 11:
 *   Same MediaStore approach for consistency, though FileObserver
 *   could also work on those versions.
 *
 * Fail-open: all MediaStore queries are wrapped in try-catch.
 * Deduplication: tracks display names and URIs to prevent duplicate alerts.
 */
class ApkFileObserver(
    private val context: Context,
    private val onApkDetected: (ApkFileInfo) -> Unit
) {
    companion object {
        private const val TAG = "BG_ApkFileObserver"

        // Directories of interest (used for path filtering)
        private val watchedPathSegments = listOf(
            "download", "downloads",
            "whatsapp", "wa business",
            "telegram",
            "bluetooth",
            "received files",
            "shareit"
        )
    }

    private val handler = Handler(Looper.getMainLooper())
    private var mediaObserver: ContentObserver? = null
    private val reportedFiles = ConcurrentHashMap<String, Long>()
    @Volatile private var isRunning = false

    // Track the timestamp from which to look for new entries
    private var lastScanTimestamp = System.currentTimeMillis() / 1000

    /**
     * Start monitoring MediaStore for new APK files.
     * Safe to call multiple times; will no-op if already running.
     */
    fun start() {
        if (isRunning) return
        isRunning = true
        lastScanTimestamp = (System.currentTimeMillis() / 1000) - 86400 // Scan files from the last 24 hours on startup

        try {
            mediaObserver = object : ContentObserver(handler) {
                override fun onChange(selfChange: Boolean, uri: Uri?) {
                    super.onChange(selfChange, uri)
                    handler.postDelayed({
                        queryNewApkFiles(uri)
                    }, 1500) // Small delay to let MediaStore index the file
                }
            }

            // Register for both internal and external storage changes
            val contentResolver = context.contentResolver
            contentResolver.registerContentObserver(
                MediaStore.Files.getContentUri("external"),
                true,
                mediaObserver!!
            )

            Log.i(TAG, "APK file observer started via MediaStore")

            // Do an initial scan for any recent APKs
            handler.postDelayed({ queryNewApkFiles(null) }, 2000)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start APK file observer: ${e.message}")
            isRunning = false
        }
    }

    /**
     * Stop monitoring and release resources.
     */
    fun stop() {
        if (!isRunning) return
        isRunning = false
        try {
            mediaObserver?.let {
                context.contentResolver.unregisterContentObserver(it)
            }
            mediaObserver = null
            Log.i(TAG, "APK file observer stopped")
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping APK file observer: ${e.message}")
        }
    }

    /**
     * Query MediaStore for APK files added since the last scan or specific changed URI.
     * Filters by MIME type and file extension, then checks directory relevance.
     */
    private fun queryNewApkFiles(targetUri: Uri? = null) {
        if (!isRunning) return

        try {
            val resolver = context.contentResolver
            val projection = arrayOf(
                MediaStore.Files.FileColumns._ID,
                MediaStore.Files.FileColumns.DISPLAY_NAME,
                MediaStore.Files.FileColumns.DATA,
                MediaStore.Files.FileColumns.SIZE,
                MediaStore.Files.FileColumns.DATE_ADDED,
                MediaStore.Files.FileColumns.MIME_TYPE
            )

            val isSingleRow = targetUri != null && targetUri.lastPathSegment?.toLongOrNull() != null
            val queryUri = if (isSingleRow) targetUri!! else MediaStore.Files.getContentUri("external")
            val selection: String?
            val selectionArgs: Array<String>?
            val sortOrder: String?

            if (isSingleRow) {
                selection = null
                selectionArgs = null
                sortOrder = null
            } else {
                // Query files added after our last scan timestamp with APK or masquerade characteristics
                selection = buildString {
                    append("(")
                    append("${MediaStore.Files.FileColumns.MIME_TYPE} = 'application/vnd.android.package-archive'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.apk'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.pdf'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.png'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.jpg'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.jpeg'")
                    append(" OR ")
                    append("${MediaStore.Files.FileColumns.DISPLAY_NAME} LIKE '%.docx'")
                    append(")")
                    append(" AND ")
                    append("${MediaStore.Files.FileColumns.DATE_ADDED} >= ?")
                }
                selectionArgs = arrayOf(lastScanTimestamp.toString())
                sortOrder = "${MediaStore.Files.FileColumns.DATE_ADDED} DESC"
            }

            val cursor = resolver.query(
                queryUri,
                projection,
                selection,
                selectionArgs,
                sortOrder
            )

            cursor?.use {
                val idCol = it.getColumnIndexOrThrow(MediaStore.Files.FileColumns._ID)
                val nameCol = it.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DISPLAY_NAME)
                val dataCol = it.getColumnIndex(MediaStore.Files.FileColumns.DATA)
                val sizeCol = it.getColumnIndexOrThrow(MediaStore.Files.FileColumns.SIZE)
                val dateCol = it.getColumnIndexOrThrow(MediaStore.Files.FileColumns.DATE_ADDED)
                val mimeCol = it.getColumnIndexOrThrow(MediaStore.Files.FileColumns.MIME_TYPE)

                while (it.moveToNext()) {
                    val id = it.getLong(idCol)
                    val displayName = it.getString(nameCol) ?: "unknown.apk"
                    val filePath = if (dataCol >= 0) it.getString(dataCol) else null
                    val fileSize = it.getLong(sizeCol)
                    val dateAdded = it.getLong(dateCol)
                    val mimeType = it.getString(mimeCol)

                    // If we queried a single row, we still need to filter out files that aren't APK candidates
                    if (isSingleRow) {
                        val isCandidate = (mimeType == "application/vnd.android.package-archive") ||
                                displayName.endsWith(".apk", ignoreCase = true) ||
                                displayName.endsWith(".pdf", ignoreCase = true) ||
                                displayName.endsWith(".png", ignoreCase = true) ||
                                displayName.endsWith(".jpg", ignoreCase = true) ||
                                displayName.endsWith(".jpeg", ignoreCase = true) ||
                                displayName.endsWith(".docx", ignoreCase = true)
                        if (!isCandidate) continue
                    }

                    // Deduplication by file path or display name to prevent spam notifications during downloads
                    val dedupeKey = filePath ?: displayName
                    val lastReportTime = reportedFiles[dedupeKey]
                    if (lastReportTime != null && System.currentTimeMillis() - lastReportTime < 15000) {
                        continue
                    }
                    reportedFiles[dedupeKey] = System.currentTimeMillis()

                    // Determine the source directory
                    val sourceDir = extractSourceDirectory(filePath)

                    // Check if this is from a watched directory
                    val isFromWatchedDir = filePath?.let { path ->
                        val lowerPath = path.lowercase()
                        watchedPathSegments.any { seg -> lowerPath.contains(seg) }
                    } ?: true // If no path info, assume it's relevant

                    val info = ApkFileInfo(
                        id = id,
                        displayName = displayName,
                        filePath = filePath,
                        fileSize = fileSize,
                        dateAdded = dateAdded,
                        mimeType = mimeType,
                        sourceDirectory = sourceDir,
                        isFromWatchedDir = isFromWatchedDir
                    )

                    // 1. Perform background/immediate threat analysis in Kotlin
                    val extension = if (filePath != null) java.io.File(filePath).extension.lowercase() else ""
                    
                    var isZipHeader = false
                    if (filePath != null) {
                        try {
                            java.io.FileInputStream(java.io.File(filePath)).use { fis ->
                                val header = ByteArray(4)
                                val read = fis.read(header)
                                if (read >= 4) {
                                    isZipHeader = header[0] == 0x50.toByte() && header[1] == 0x4B.toByte()
                                }
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Error checking magic bytes in background: ${e.message}")
                        }
                    }

                    var isApkStructure = false
                    if (filePath != null) {
                        val file = java.io.File(filePath)
                        try {
                            java.util.zip.ZipFile(file).use { zip ->
                                val hasManifest = zip.getEntry("AndroidManifest.xml") != null
                                val hasDex = zip.getEntry("classes.dex") != null
                                isApkStructure = hasManifest && hasDex
                            }
                        } catch (e: Exception) {
                            // Not a valid zip
                        }

                        if (!isApkStructure) {
                            val hasManifestPattern = fileContainsPattern(file, "AndroidManifest.xml".toByteArray(Charsets.UTF_8))
                            val hasDexPattern = fileContainsPattern(file, "classes.dex".toByteArray(Charsets.UTF_8))
                            isApkStructure = hasManifestPattern && hasDexPattern
                        }
                    }

                    val isApk = isApkStructure
                    val isPolyglot = isApk && (extension != "apk" || !isZipHeader)

                    if (isPolyglot) {
                        Log.i(TAG, "Background check: Detected polyglot APK threat: $displayName")
                        showKotlinNotification(
                            "🚨 BankGuard Critical Alert",
                            "Dangerous disguised app package (Polyglot) detected: $displayName. Tap to secure device."
                        )
                        // Trigger immediate system warning overlay window on spot!
                        ThreatOverlayWindow.show(context, displayName, extension, filePath)
                    } else if (isApk) {
                        Log.i(TAG, "Background check: Detected standard APK download: $displayName")
                        showKotlinNotification(
                            "BankGuard: New App Downloaded",
                            "Verifying installation package security for $displayName..."
                        )
                    }

                    Log.i(TAG, "APK file detected: $displayName (${sourceDir ?: "unknown dir"})")
                    onApkDetected(info)
                }
            }

            // Update the timestamp for next scan
            lastScanTimestamp = System.currentTimeMillis() / 1000

            // Prune old deduplication entries (older than 1 hour)
            pruneDeduplicationCache()
        } catch (e: Exception) {
            Log.w(TAG, "MediaStore APK query failed: ${e.message}")
        }
    }

    /**
     * Extract a human-readable source directory from the full file path.
     */
    private fun extractSourceDirectory(filePath: String?): String? {
        if (filePath == null) return null
        val lower = filePath.lowercase()
        return when {
            lower.contains("/whatsapp/") -> "WhatsApp"
            lower.contains("/wa business/") -> "WhatsApp Business"
            lower.contains("/telegram/") -> "Telegram"
            lower.contains("/bluetooth/") -> "Bluetooth"
            lower.contains("/download") -> "Downloads"
            lower.contains("/shareit/") -> "SHAREit"
            lower.contains("/received files/") -> "Received Files"
            else -> {
                // Return the parent directory name
                val segments = filePath.split("/")
                if (segments.size >= 2) segments[segments.size - 2] else null
            }
        }
    }

    /**
     * Remove deduplication entries older than 1 hour.
     */
    private fun pruneDeduplicationCache() {
        val cutoff = System.currentTimeMillis() - 3600_000
        reportedFiles.entries.removeIf { it.value < cutoff }
    }

    private fun fileContainsPattern(file: java.io.File, pattern: ByteArray): Boolean {
        try {
            java.io.FileInputStream(file).use { fis ->
                val buffer = ByteArray(4096)
                var bytesRead = fis.read(buffer)
                val patternSize = pattern.size
                if (patternSize == 0) return false
                
                var prevBufferTail = ByteArray(0)
                
                while (bytesRead != -1) {
                    val searchData = if (prevBufferTail.isEmpty()) {
                        buffer.copyOf(bytesRead)
                    } else {
                        val merged = ByteArray(prevBufferTail.size + bytesRead)
                        System.arraycopy(prevBufferTail, 0, merged, 0, prevBufferTail.size)
                        System.arraycopy(buffer, 0, merged, prevBufferTail.size, bytesRead)
                        merged
                    }
                    
                    for (i in 0..searchData.size - patternSize) {
                        var found = true
                        for (j in 0 until patternSize) {
                            if (searchData[i + j] != pattern[j]) {
                                                    found = false
                                                    break
                                                }
                                            }
                        if (found) return true
                    }
                    
                    if (bytesRead >= patternSize) {
                        prevBufferTail = buffer.copyOfRange(bytesRead - patternSize + 1, bytesRead)
                    } else {
                        prevBufferTail = ByteArray(0)
                    }
                    
                    bytesRead = fis.read(buffer)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error scanning file for pattern", e)
        }
        return false
    }

    /**
     * APK file detection info pushed to the Dart layer.
     */
    data class ApkFileInfo(
        val id: Long,
        val displayName: String,
        val filePath: String?,
        val fileSize: Long,
        val dateAdded: Long,
        val mimeType: String?,
        val sourceDirectory: String?,
        val isFromWatchedDir: Boolean
    ) {
        fun toChannelMap(): HashMap<String, Any?> {
            return hashMapOf(
                "id" to id,
                "displayName" to displayName,
                "filePath" to filePath,
                "fileSize" to fileSize,
                "dateAdded" to dateAdded,
                "mimeType" to mimeType,
                "sourceDirectory" to sourceDirectory,
                "isFromWatchedDir" to isFromWatchedDir
            )
        }
    }

    private fun showKotlinNotification(title: String, message: String) {
        try {
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channelId = "bankguard_threats"
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    channelId,
                    "BankGuard Threat Alerts",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Real-time alerts for downloaded threats"
                    enableLights(true)
                    lightColor = android.graphics.Color.RED
                    enableVibration(true)
                }
                notificationManager.createNotificationChannel(channel)
            }

            val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)?.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            }
            val pendingIntent = PendingIntent.getActivity(
                context,
                1002,
                launchIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                Notification.Builder(context, channelId)
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(context)
            }

            val notification = builder
                .setContentTitle(title)
                .setContentText(message)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setPriority(Notification.PRIORITY_HIGH)
                .setDefaults(Notification.DEFAULT_ALL)
                .build()

            notificationManager.notify(2003, notification)
            Log.i(TAG, "Heads-up notification posted: $title - $message")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show Kotlin notification: ${e.message}", e)
        }
    }
}
