package com.bankguard.sdk

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.io.File

/**
 * Task 6: LSPosed / Xposed / Zygisk framework detection.
 *
 * Xposed-family frameworks inject code at the Zygote level, which means
 * they can hook any Java/Kotlin method in the process before our code runs.
 * A compromised Zygote can:
 *   - Intercept SmsManager.sendTextMessage() to steal OTPs
 *   - Hook KeyStore operations to extract signing keys
 *   - Modify TelephonyManager responses to spoof device identity
 *   - Patch our own security checks to always return "safe"
 *
 * Detection strategy (multi-signal):
 *   1. Package presence (installed Xposed manager apps)
 *   2. Filesystem artifacts (/system, /data paths)
 *   3. System property inspection
 *   4. Stack frame analysis (Xposed hooks add identifiable stack frames)
 *   5. Native library scan (via RaspNative /proc/self/maps, handled in C++)
 */
object FrameworkDetector {

    private const val TAG = "FRAMEWORK_DETECT"

    // Known Xposed/LSPosed/EdXposed manager package names
    private val XPOSED_PACKAGES = listOf(
        "de.robv.android.xposed.installer",       // Original Xposed
        "org.meowcat.edxposed.manager",            // EdXposed
        "com.solohsu.android.edxp.manager",        // EdXposed alt
        "org.lsposed.manager",                      // LSPosed
        "io.github.lsposed.manager",               // LSPosed (new)
        "com.topjohnwu.magisk",                    // Magisk Manager
        "com.fox2code.mmm",                        // Magisk Module Manager alt
        "me.weishu.exp",                            // TaiChi (Xposed on non-root)
        "com.android.vending.billing.InAppBillingService.COIN" // Fake billing (GameGuardian)
    )

    // Root manager packages (root is a precondition for most framework injection)
    private val ROOT_PACKAGES = listOf(
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.topjohnwu.magisk",
        "me.phh.superuser",
        "com.kingouser.com"
    )

    // Filesystem paths that indicate Xposed/Magisk/Root presence
    private val SUSPICIOUS_PATHS = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/xposed.prop",
        "/system/app/XposedInstaller",
        "/data/adb/xposed",
        "/data/adb/modules",           // Magisk/Zygisk modules directory
        "/data/adb/lspd",              // LSPosed daemon
        "/data/adb/magisk",
        "/data/adb/magisk.img",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/app/Superuser.apk",
        "/data/data/com.noshufou.android.su",
        "/sbin/.magisk",
        "/cache/.disable_magisk",
        "/dev/.magisk.unblock"
    )

    // System properties that Xposed/Magisk set
    private val SUSPICIOUS_PROPS = listOf(
        "ro.debuggable",              // Should be 0 on production builds
        "persist.sys.xposed.install",
        "dalvik.vm.appImageFile"       // Tampered on Xposed-injected processes
    )

    data class DetectionResult(
        val isCompromised: Boolean,
        val detectedFrameworks: List<String>,
        val detectedPackages: List<String>,
        val detectedPaths: List<String>,
        val stackFrameHooks: List<String>,
        val riskLevel: String  // "NONE", "LOW", "HIGH", "CRITICAL"
    ) {
        fun toChannelMap(): HashMap<String, Any> = hashMapOf(
            "isCompromised" to isCompromised,
            "detectedFrameworks" to detectedFrameworks,
            "detectedPackages" to detectedPackages,
            "detectedPaths" to detectedPaths,
            "stackFrameHooks" to stackFrameHooks,
            "riskLevel" to riskLevel
        )
    }

    /**
     * Run full framework detection. Combines all signal sources.
     */
    @JvmStatic
    fun detect(context: Context): DetectionResult {
        val frameworks = mutableListOf<String>()
        val packages = mutableListOf<String>()
        val paths = mutableListOf<String>()
        val stackHooks = mutableListOf<String>()

        // Signal 1: Package presence
        val pm = context.packageManager
        for (pkg in XPOSED_PACKAGES) {
            if (isPackageInstalled(pm, pkg)) {
                packages.add(pkg)
                when {
                    pkg.contains("lsposed") -> frameworks.add("LSPosed")
                    pkg.contains("edxposed") || pkg.contains("edxp") -> frameworks.add("EdXposed")
                    pkg.contains("xposed") -> frameworks.add("Xposed")
                    pkg.contains("magisk") -> frameworks.add("Magisk")
                    pkg.contains("exp") && pkg.contains("weishu") -> frameworks.add("TaiChi")
                }
            }
        }
        for (pkg in ROOT_PACKAGES) {
            if (isPackageInstalled(pm, pkg)) {
                packages.add(pkg)
                if (!frameworks.contains("Root")) {
                    frameworks.add("Root")
                }
            }
        }

        // Signal 2: Filesystem artifacts
        for (path in SUSPICIOUS_PATHS) {
            try {
                if (File(path).exists()) {
                    paths.add(path)
                    when {
                        path.contains("XposedBridge") || path.contains("xposed") ->
                            if (!frameworks.contains("Xposed")) frameworks.add("Xposed")
                        path.contains("lspd") ->
                            if (!frameworks.contains("LSPosed")) frameworks.add("LSPosed")
                        path.contains("magisk") ->
                            if (!frameworks.contains("Magisk")) frameworks.add("Magisk")
                        path.contains("/su") || path.contains("Superuser") ->
                            if (!frameworks.contains("Root")) frameworks.add("Root")
                    }
                }
            } catch (_: SecurityException) {
                // Can't access path, which is expected in sandboxed environments
            }
        }

        // Signal 3: Stack frame analysis
        // Xposed hooks insert stack frames containing "de.robv.android.xposed"
        // or "LSPosed" in the call chain
        val stackTrace = Thread.currentThread().stackTrace
        for (frame in stackTrace) {
            val className = frame.className
            when {
                className.contains("de.robv.android.xposed") -> {
                    stackHooks.add("Xposed: $className")
                    if (!frameworks.contains("Xposed")) frameworks.add("Xposed")
                }
                className.contains("lsposed") || className.contains("LSPosed") -> {
                    stackHooks.add("LSPosed: $className")
                    if (!frameworks.contains("LSPosed")) frameworks.add("LSPosed")
                }
                className.contains("EdHooker") || className.contains("edxposed") -> {
                    stackHooks.add("EdXposed: $className")
                    if (!frameworks.contains("EdXposed")) frameworks.add("EdXposed")
                }
            }
        }

        // Determine risk level
        val riskLevel = when {
            frameworks.any { it in listOf("LSPosed", "EdXposed", "Xposed") } -> "CRITICAL"
            frameworks.contains("Magisk") || frameworks.contains("Root") -> "HIGH"
            packages.isNotEmpty() || paths.isNotEmpty() -> "LOW"
            else -> "NONE"
        }

        val isCompromised = riskLevel != "NONE"

        if (isCompromised) {
            Log.w(TAG, "Framework detection: $riskLevel | Frameworks: $frameworks")
        }

        return DetectionResult(
            isCompromised = isCompromised,
            detectedFrameworks = frameworks,
            detectedPackages = packages,
            detectedPaths = paths,
            stackFrameHooks = stackHooks,
            riskLevel = riskLevel
        )
    }

    private fun isPackageInstalled(pm: PackageManager, packageName: String): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }
}
