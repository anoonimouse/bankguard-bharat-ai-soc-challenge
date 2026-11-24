package com.bankguard.sdk

import android.content.Context
import android.database.ContentObserver
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/**
 * Monitors the "Unknown Sources" / "Install from Unknown Apps" setting in real-time.
 *
 * Registers a ContentObserver against Settings.Secure so changes are detected
 * within seconds, not only at app startup. Fires a callback whenever the
 * state transitions (enabled or disabled).
 *
 * On Android O+ (API 26), "Unknown Sources" is per-app via canRequestPackageInstalls().
 * On older versions, it's a global toggle via INSTALL_NON_MARKET_APPS.
 */
class UnknownSourcesObserver(
    private val context: Context,
    private val onStateChanged: (Boolean) -> Unit
) {
    private var observer: ContentObserver? = null
    private var lastKnownState: Boolean? = null

    /** Start monitoring. Fires initial state via callback. */
    fun start() {
        val currentState = isUnknownSourcesEnabled()
        lastKnownState = currentState
        // Fire initial state so the Dart side knows immediately
        onStateChanged(currentState)

        observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                super.onChange(selfChange)
                val newState = isUnknownSourcesEnabled()
                if (newState != lastKnownState) {
                    lastKnownState = newState
                    onStateChanged(newState)
                }
            }
        }

        // The URI to observe depends on the Android version.
        // On pre-O, INSTALL_NON_MARKET_APPS is a single global setting.
        // On O+, we observe the broader Secure settings since per-app control
        // doesn't have a specific content URI for individual apps.
        val uri = if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            Settings.Secure.getUriFor(Settings.Secure.INSTALL_NON_MARKET_APPS)
        } else {
            // Broad Secure settings observer; will trigger on many changes,
            // but the onChange handler filters to only fire on actual state transitions
            Settings.Secure.CONTENT_URI
        }

        context.contentResolver.registerContentObserver(uri, true, observer!!)
    }

    /** Stop monitoring and release observer. */
    fun stop() {
        observer?.let {
            try {
                context.contentResolver.unregisterContentObserver(it)
            } catch (_: Exception) {
                // Observer may already be unregistered
            }
        }
        observer = null
    }

    /** Current state of the Unknown Sources setting. */
    fun isUnknownSourcesEnabled(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.packageManager.canRequestPackageInstalls()
            } else {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(
                    context.contentResolver,
                    Settings.Secure.INSTALL_NON_MARKET_APPS,
                    0
                ) == 1
            }
        } catch (_: Exception) {
            false
        }
    }

    /** Current state for diagnostics. */
    fun isMonitoring(): Boolean = observer != null
}
