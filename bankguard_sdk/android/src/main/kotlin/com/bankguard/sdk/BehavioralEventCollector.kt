package com.bankguard.sdk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Lightweight background event collector for the behavioral engine.
 *
 * Listens for security-relevant system events and feeds them into
 * the [BehavioralProfileStore] for risk scoring:
 *
 * - Package install/uninstall via ACTION_PACKAGE_ADDED/REMOVED
 * - Accessibility settings changes via ContentObserver
 * - Overlay permission changes via periodic check on scan (polled on event, not timer)
 *
 * All event handlers return immediately - heavy computation is deferred
 * to a single-thread background executor.
 */
class BehavioralEventCollector(
    private val context: Context,
    private val store: BehavioralProfileStore,
    private val scorer: BehavioralRiskScorer,
    private val timeWindowManager: TimeWindowManager,
    private val apkDenylist: ApkHashDenylist? = null,
    private val onThreatDetected: ((BehavioralProfile) -> Unit)? = null
) {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private var packageReceiver: BroadcastReceiver? = null
    private var accessibilityObserver: ContentObserver? = null
    private var isRunning = false

    /** Start listening for system events. Idempotent. */
    fun start() {
        if (isRunning) return
        isRunning = true
        registerPackageReceiver()
        registerAccessibilityObserver()
    }

    /** Stop listening and release resources. */
    fun stop() {
        isRunning = false
        unregisterPackageReceiver()
        unregisterAccessibilityObserver()
    }

    // -----------------------------------------------------------------------
    // Package Install / Uninstall
    // -----------------------------------------------------------------------

    private fun registerPackageReceiver() {
        if (packageReceiver != null) return

        packageReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context?, intent: Intent?) {
                if (intent == null || ctx == null) return
                val data: Uri = intent.data ?: return
                val pkg = data.schemeSpecificPart ?: return

                executor.submit {
                    when (intent.action) {
                        Intent.ACTION_PACKAGE_ADDED -> handlePackageInstalled(ctx, pkg)
                        Intent.ACTION_PACKAGE_REMOVED -> handlePackageRemoved(pkg)
                    }
                }
            }
        }

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }

        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(packageReceiver, filter, Context.RECEIVER_EXPORTED)
        } else {
            context.registerReceiver(packageReceiver, filter)
        }
    }

    private fun unregisterPackageReceiver() {
        if (packageReceiver != null) {
            try { context.unregisterReceiver(packageReceiver) } catch (_: Exception) {}
            packageReceiver = null
        }
    }

    private fun handlePackageInstalled(ctx: Context, packageName: String) {
        val now = System.currentTimeMillis()
        val source = determineInstallSource(ctx, packageName)
        val hasBanking = BehavioralProfile.containsBankingKeywords(packageName)

        var appLabel = ""
        try {
            val appInfo = ctx.packageManager.getApplicationInfo(packageName, 0)
            appLabel = ctx.packageManager.getApplicationLabel(appInfo).toString()
            if (!hasBanking && BehavioralProfile.containsBankingKeywords(appLabel)) {
                // App label contains banking keywords even if package name doesn't
            }
        } catch (_: Exception) {}

        val profile = BehavioralProfile(
            packageName = packageName,
            installTimestampMs = now,
            installSource = source,
            appLabel = appLabel,
            hasBankingKeywords = hasBanking || BehavioralProfile.containsBankingKeywords(appLabel),
            currentStage = 1,
            lastUpdatedMs = now,
            events = mutableListOf(
                BehavioralEvent(
                    type = BehavioralEvent.INSTALLED,
                    timestampMs = now,
                    detail = "source=${source.label}"
                )
            )
        )

        // Score and store
        val result = scorer.score(profile)
        profile.lastScore = result.score
        profile.lastVerdict = result.verdict
        store.put(profile)

        // Check against APK hash denylist (Layer 4B)
        val deniedHash = apkDenylist?.checkPackage(ctx, packageName)
        if (deniedHash != null) {
            profile.lastScore = 100
            profile.lastVerdict = "DENIED"
            profile.events.add(
                BehavioralEvent(
                    type = BehavioralEvent.INSTALLED,
                    timestampMs = now,
                    detail = "denylist_match=hash:${deniedHash.take(16)}..."
                )
            )
            store.put(profile)
            // Force alert regardless of previous alert state
            profile.alertFired = false
        }

        checkAndFireAlert(profile, if (deniedHash != null) {
            BehavioralRiskScorer.ScoringResult(100, "DENIED")
        } else {
            result
        })
    }

    private fun handlePackageRemoved(packageName: String) {
        store.remove(packageName)
    }

    @Suppress("DEPRECATION")
    private fun determineInstallSource(ctx: Context, packageName: String): InstallSource {
        return try {
            val installer: String? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                ctx.packageManager.getInstallSourceInfo(packageName).installingPackageName
            } else {
                ctx.packageManager.getInstallerPackageName(packageName)
            }

            when {
                installer == null -> InstallSource.UNKNOWN
                installer.contains("vending") || installer.contains("play") -> InstallSource.PLAY_STORE
                installer.contains("browser") || installer.contains("chrome") || installer.contains("firefox") -> InstallSource.BROWSER
                installer.contains("filemanager") || installer.contains("files") -> InstallSource.FILE_MANAGER
                installer.contains("shell") || installer.contains("adb") -> InstallSource.ADB
                else -> InstallSource.UNKNOWN
            }
        } catch (_: Exception) {
            InstallSource.UNKNOWN
        }
    }

    // -----------------------------------------------------------------------
    // Accessibility Settings Observer
    // -----------------------------------------------------------------------

    private fun registerAccessibilityObserver() {
        if (accessibilityObserver != null) return

        val handler = Handler(Looper.getMainLooper())
        accessibilityObserver = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean) {
                executor.submit { handleAccessibilityChange() }
            }
        }

        try {
            context.contentResolver.registerContentObserver(
                Settings.Secure.getUriFor(Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
                false,
                accessibilityObserver!!
            )
        } catch (_: Exception) {
            // Some devices restrict this
        }
    }

    private fun unregisterAccessibilityObserver() {
        if (accessibilityObserver != null) {
            try { context.contentResolver.unregisterContentObserver(accessibilityObserver!!) } catch (_: Exception) {}
            accessibilityObserver = null
        }
    }

    private fun handleAccessibilityChange() {
        val now = System.currentTimeMillis()
        val enabledServices = try {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            ) ?: ""
        } catch (_: Exception) { "" }

        // Check every monitored profile to see if its package now has accessibility
        for (profile in store.getAll()) {
            val hadAccessibility = profile.accessibilityEnabledMs > 0
            val hasAccessibility = enabledServices.lowercase().contains(profile.packageName.lowercase())

            if (hasAccessibility && !hadAccessibility) {
                profile.accessibilityEnabledMs = now
                profile.currentStage = maxOf(profile.currentStage, 3)
                profile.lastUpdatedMs = now
                profile.events.add(
                    BehavioralEvent(
                        type = BehavioralEvent.ACCESSIBILITY_ENABLED,
                        timestampMs = now
                    )
                )
                val result = scorer.score(profile)
                profile.lastScore = result.score
                profile.lastVerdict = result.verdict
                store.put(profile)
                checkAndFireAlert(profile, result)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Overlay Permission Check (called during re-evaluation)
    // -----------------------------------------------------------------------

    /**
     * Called during device scan or re-evaluation to update overlay permission
     * status for all monitored profiles.
     */
    fun refreshOverlayStatus() {
        executor.submit {
            val now = System.currentTimeMillis()
            val appOps = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                context.getSystemService(Context.APP_OPS_SERVICE) as android.app.AppOpsManager
            } else null

            for (profile in store.getAll()) {
                if (profile.overlayGrantedMs > 0) continue

                // Skip host app - it needs overlay for its own protection layers
                if (profile.packageName == context.packageName) continue

                val hasOverlay = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && appOps != null) {
                        val uid = try {
                            context.packageManager.getPackageUid(profile.packageName, 0)
                        } catch (_: Exception) { -1 }
                        
                        if (uid != -1) {
                            val mode = appOps.checkOpNoThrow(
                                android.app.AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                                uid,
                                profile.packageName
                            )
                            mode == android.app.AppOpsManager.MODE_ALLOWED
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } catch (_: Exception) { false }

                if (hasOverlay) {
                    profile.overlayGrantedMs = now
                    profile.currentStage = maxOf(profile.currentStage, 2)
                    profile.lastUpdatedMs = now
                    profile.events.add(
                        BehavioralEvent(
                            type = BehavioralEvent.OVERLAY_GRANTED,
                            timestampMs = now
                        )
                    )
                    val result = scorer.score(profile)
                    profile.lastScore = result.score
                    profile.lastVerdict = result.verdict
                    store.put(profile)
                    checkAndFireAlert(profile, result)
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Alert Firing
    // -----------------------------------------------------------------------

    private fun checkAndFireAlert(profile: BehavioralProfile, result: BehavioralRiskScorer.ScoringResult) {
        // Fire alert when crossing into SUSPICIOUS or higher, or on stage advancement
        val shouldAlert = !profile.alertFired && result.score >= 51
        if (shouldAlert) {
            profile.alertFired = true
            store.put(profile)
            onThreatDetected?.invoke(profile)
        }
    }
}
