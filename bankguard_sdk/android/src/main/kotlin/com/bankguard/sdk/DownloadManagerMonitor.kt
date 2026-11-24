package com.bankguard.sdk

import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.Cursor
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.util.concurrent.ConcurrentHashMap

/**
 * Monitors DownloadManager for APK file downloads.
 *
 * Two detection mechanisms:
 *   1. BroadcastReceiver on DownloadManager.ACTION_DOWNLOAD_COMPLETE
 *      — fires when any download finishes, and we check if it's an APK
 *   2. Active polling via Handler — periodically queries DownloadManager
 *      for in-progress or recently completed APK downloads
 *
 * Detected APK downloads are reported via [onApkDownloadDetected] callback.
 * The monitor is non-blocking and fail-open by design.
 */
class DownloadManagerMonitor(
    private val context: Context,
    private val onApkDownloadDetected: (ApkDownloadInfo) -> Unit
) {
    private var downloadReceiver: BroadcastReceiver? = null
    private val handler = Handler(Looper.getMainLooper())
    private var isPolling = false

    // Track already-reported download IDs to avoid duplicate alerts
    private val reportedDownloads = ConcurrentHashMap.newKeySet<Long>()

    companion object {
        private const val POLL_INTERVAL_MS = 30_000L  // 30 seconds
        private const val APK_MIME = "application/vnd.android.package-archive"
        private const val MAX_TRACKED_DOWNLOADS = 100
    }

    /** Data class for a detected APK download. */
    data class ApkDownloadInfo(
        val downloadId: Long,
        val uri: String,
        val localFilePath: String?,
        val title: String?,
        val status: Int,     // DownloadManager.STATUS_*
        val totalBytes: Long,
        val downloadedBytes: Long,
        val mimeType: String?
    ) {
        /** Convert to a channel-friendly map for the Dart bridge. */
        fun toChannelMap(): HashMap<String, Any?> = hashMapOf(
            "downloadId" to downloadId,
            "uri" to uri,
            "localFilePath" to localFilePath,
            "title" to title,
            "status" to status,
            "totalBytes" to totalBytes,
            "downloadedBytes" to downloadedBytes,
            "mimeType" to mimeType,
            "isComplete" to (status == DownloadManager.STATUS_SUCCESSFUL)
        )
    }

    /** Start monitoring. Registers the receiver and begins polling. */
    fun start() {
        registerCompletionReceiver()
        startPolling()
    }

    /** Stop monitoring. Unregisters receiver and stops polling. */
    fun stop() {
        stopPolling()
        unregisterCompletionReceiver()
        reportedDownloads.clear()
    }

    // -----------------------------------------------------------------------
    // Mechanism 1: Completion BroadcastReceiver
    // -----------------------------------------------------------------------

    private fun registerCompletionReceiver() {
        if (downloadReceiver != null) return

        downloadReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent?.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE) return
                val downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1)
                if (downloadId == -1L) return
                checkDownloadAndReport(downloadId)
            }
        }

        val filter = IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(downloadReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(downloadReceiver, filter)
        }
    }

    private fun unregisterCompletionReceiver() {
        downloadReceiver?.let {
            try {
                context.unregisterReceiver(it)
            } catch (_: Exception) {}
        }
        downloadReceiver = null
    }

    // -----------------------------------------------------------------------
    // Mechanism 2: Active Polling
    // -----------------------------------------------------------------------

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!isPolling) return
            scanForApkDownloads()
            handler.postDelayed(this, POLL_INTERVAL_MS)
        }
    }

    private fun startPolling() {
        if (isPolling) return
        isPolling = true
        handler.postDelayed(pollRunnable, POLL_INTERVAL_MS)
    }

    private fun stopPolling() {
        isPolling = false
        handler.removeCallbacks(pollRunnable)
    }

    // -----------------------------------------------------------------------
    // Core Detection Logic
    // -----------------------------------------------------------------------

    /**
     * Check a specific download ID and report if it's an APK.
     */
    private fun checkDownloadAndReport(downloadId: Long) {
        if (reportedDownloads.contains(downloadId)) return

        val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as? DownloadManager ?: return
        val query = DownloadManager.Query().setFilterById(downloadId)
        var cursor: Cursor? = null

        try {
            cursor = dm.query(query)
            if (cursor != null && cursor.moveToFirst()) {
                val info = extractDownloadInfo(cursor, downloadId)
                if (isApkDownload(info)) {
                    trackAndReport(info)
                }
            }
        } catch (_: Exception) {
            // Fail-open: if we can't query the download, skip it
        } finally {
            cursor?.close()
        }
    }

    /**
     * Scan all recent downloads for APK files.
     * Called periodically by the poll handler.
     */
    private fun scanForApkDownloads() {
        val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as? DownloadManager ?: return

        // Query for running + successful downloads
        val query = DownloadManager.Query().setFilterByStatus(
            DownloadManager.STATUS_RUNNING or DownloadManager.STATUS_SUCCESSFUL
        )

        var cursor: Cursor? = null
        try {
            cursor = dm.query(query)
            if (cursor == null) return

            while (cursor.moveToNext()) {
                val idCol = cursor.getColumnIndex(DownloadManager.COLUMN_ID)
                val downloadId = if (idCol >= 0) cursor.getLong(idCol) else continue

                if (reportedDownloads.contains(downloadId)) continue

                val info = extractDownloadInfo(cursor, downloadId)
                if (isApkDownload(info)) {
                    trackAndReport(info)
                }
            }
        } catch (_: Exception) {
            // Fail-open
        } finally {
            cursor?.close()
        }
    }

    /**
     * Extract download metadata from a cursor row.
     */
    private fun extractDownloadInfo(cursor: Cursor, downloadId: Long): ApkDownloadInfo {
        fun getStringCol(name: String): String? {
            val idx = cursor.getColumnIndex(name)
            return if (idx >= 0) cursor.getString(idx) else null
        }
        fun getLongCol(name: String): Long {
            val idx = cursor.getColumnIndex(name)
            return if (idx >= 0) cursor.getLong(idx) else 0L
        }
        fun getIntCol(name: String): Int {
            val idx = cursor.getColumnIndex(name)
            return if (idx >= 0) cursor.getInt(idx) else 0
        }

        return ApkDownloadInfo(
            downloadId = downloadId,
            uri = getStringCol(DownloadManager.COLUMN_URI) ?: "",
            localFilePath = getStringCol(DownloadManager.COLUMN_LOCAL_URI),
            title = getStringCol(DownloadManager.COLUMN_TITLE),
            status = getIntCol(DownloadManager.COLUMN_STATUS),
            totalBytes = getLongCol(DownloadManager.COLUMN_TOTAL_SIZE_BYTES),
            downloadedBytes = getLongCol(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR),
            mimeType = getStringCol(DownloadManager.COLUMN_MEDIA_TYPE)
        )
    }

    /**
     * Determine if a download is an APK file based on MIME type,
     * file extension, or URL pattern.
     */
    private fun isApkDownload(info: ApkDownloadInfo): Boolean {
        // Check MIME type
        if (info.mimeType?.equals(APK_MIME, ignoreCase = true) == true) return true

        // Check URI for .apk extension
        val uriLower = info.uri.lowercase()
        if (uriLower.endsWith(".apk") || uriLower.contains(".apk?")) return true

        // Check local file path for .apk extension
        val pathLower = info.localFilePath?.lowercase() ?: ""
        if (pathLower.endsWith(".apk")) return true

        return false
    }

    /**
     * Track and report an APK download, preventing duplicates.
     */
    private fun trackAndReport(info: ApkDownloadInfo) {
        // Prevent unbounded memory growth
        if (reportedDownloads.size >= MAX_TRACKED_DOWNLOADS) {
            reportedDownloads.clear()
        }
        reportedDownloads.add(info.downloadId)
        onApkDownloadDetected(info)
    }
}
