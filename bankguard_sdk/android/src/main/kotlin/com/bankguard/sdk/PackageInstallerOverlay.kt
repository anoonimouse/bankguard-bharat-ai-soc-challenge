package com.bankguard.sdk

import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Package Installer Overlay Warning (Layer 3).
 *
 * Detects when the Android package installer is in the foreground
 * and displays a full-width warning banner at the top of the screen.
 * Requires SYSTEM_ALERT_WINDOW permission.
 *
 * Detection uses UsageStatsManager to poll the foreground app every 2 seconds.
 * When a package installer is detected, the warning overlay appears.
 * When the installer exits, the overlay is dismissed automatically.
 *
 * The overlay is non-interactive (passes touch events through) to avoid
 * blocking the user — it's an awareness tool, not a blocker.
 */
class PackageInstallerOverlay(
    private val context: Context,
    private val onInstallerDetected: (() -> Unit)? = null
) {
    private val handler = Handler(Looper.getMainLooper())
    private var isMonitoring = false
    private var overlayView: View? = null
    private var windowManager: WindowManager? = null
    private var isOverlayShowing = false

    companion object {
        private const val POLL_INTERVAL_MS = 2000L

        // Known package installer package names across OEMs
        private val INSTALLER_PACKAGES = setOf(
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.samsung.android.packageinstaller",
            "com.miui.packageinstaller",
            "com.miui.securitycenter",
            "com.coloros.safecenter",
            "com.bbk.appstore",
            "com.huawei.systemmanager"
        )
    }

    /** Start monitoring for the package installer. */
    fun start() {
        if (isMonitoring) return
        if (!hasOverlayPermission()) return

        windowManager = context.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
        isMonitoring = true
        handler.postDelayed(pollRunnable, POLL_INTERVAL_MS)
    }

    /** Stop monitoring and dismiss any active overlay. */
    fun stop() {
        isMonitoring = false
        handler.removeCallbacks(pollRunnable)
        dismissOverlay()
    }

    /** Check if the app has SYSTEM_ALERT_WINDOW permission. */
    fun hasOverlayPermission(): Boolean {
        return Settings.canDrawOverlays(context)
    }

    // -----------------------------------------------------------------------
    // Polling
    // -----------------------------------------------------------------------

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (!isMonitoring) return
            val foregroundPackage = getForegroundPackage()
            if (foregroundPackage != null && INSTALLER_PACKAGES.contains(foregroundPackage)) {
                if (!isOverlayShowing) {
                    showOverlay()
                    onInstallerDetected?.invoke()
                }
            } else {
                if (isOverlayShowing) {
                    dismissOverlay()
                }
            }
            handler.postDelayed(this, POLL_INTERVAL_MS)
        }
    }

    /**
     * Get the current foreground app's package name using UsageStatsManager.
     * Requires PACKAGE_USAGE_STATS permission (granted via Settings).
     * Returns null if unable to determine (fail-open).
     */
    private fun getForegroundPackage(): String? {
        return try {
            val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
                ?: return null

            val now = System.currentTimeMillis()
            val events = usm.queryEvents(now - 5000, now)
            var lastPackage: String? = null

            val event = UsageEvents.Event()
            while (events.hasNextEvent()) {
                events.getNextEvent(event)
                if (event.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND) {
                    lastPackage = event.packageName
                }
            }
            lastPackage
        } catch (_: Exception) {
            null
        }
    }

    // -----------------------------------------------------------------------
    // Overlay View
    // -----------------------------------------------------------------------

    /**
     * Show the warning overlay banner at the top of the screen.
     * The banner is a red bar with white text warning about APK installation.
     */
    private fun showOverlay() {
        if (isOverlayShowing || windowManager == null) return
        if (!hasOverlayPermission()) return

        try {
            val layout = createOverlayLayout()
            val params = createLayoutParams()

            windowManager!!.addView(layout, params)
            overlayView = layout
            isOverlayShowing = true
        } catch (_: Exception) {
            // Overlay permission may have been revoked between check and add
            isOverlayShowing = false
        }
    }

    /** Dismiss the overlay banner. */
    private fun dismissOverlay() {
        if (!isOverlayShowing || overlayView == null || windowManager == null) return
        try {
            windowManager!!.removeView(overlayView)
        } catch (_: Exception) {
            // View may already be removed
        }
        overlayView = null
        isOverlayShowing = false
    }

    /**
     * Create the native overlay layout.
     * A full-width red banner with a warning icon and two lines of text.
     */
    private fun createOverlayLayout(): LinearLayout {
        val dpToPx = { dp: Int ->
            TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP,
                dp.toFloat(),
                context.resources.displayMetrics
            ).toInt()
        }

        return LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#D32F2F"))  // Material Red 700
            setPadding(dpToPx(16), dpToPx(48), dpToPx(16), dpToPx(12))

            // Title
            addView(TextView(context).apply {
                text = "\u26A0\uFE0F SECURITY WARNING"
                setTextColor(Color.WHITE)
                textSize = 16f
                setTypeface(null, Typeface.BOLD)
                gravity = Gravity.CENTER_HORIZONTAL
            })

            // Message
            addView(TextView(context).apply {
                text = "You are about to install an APK from an unknown source. " +
                       "Official YONO SBI is ONLY available from Google Play Store. " +
                       "If you did not initiate this, press Back immediately."
                setTextColor(Color.parseColor("#FFFFFFCC"))
                textSize = 13f
                gravity = Gravity.CENTER_HORIZONTAL
                setPadding(0, dpToPx(4), 0, 0)
            })
        }
    }

    /**
     * Create WindowManager layout parameters for the overlay.
     * Uses TYPE_APPLICATION_OVERLAY (API 26+) or TYPE_SYSTEM_ALERT (legacy).
     * Configured to be non-focusable and pass-through for touches.
     */
    @Suppress("DEPRECATION")
    private fun createLayoutParams(): WindowManager.LayoutParams {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }

        return WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            type,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP
        }
    }
}
