package com.bankguard.sdk

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log

/**
 * Kotlin bridge to the native C++ RASP layer (librasp_native.so).
 *
 * Provides static JNI methods that map directly to the C exports in rasp_native.cpp:
 *   - scanProcessMaps()    -> Task 1: Memory audit
 *   - verifyDexIntegrity() -> Task 2: DEX checksum attestation
 *   - auditSigsysHandler() -> Task 4: SIGSYS + latency profiling
 *   - runFullAudit()       -> Combined health check
 *
 * All methods run on the calling thread. For UI-safe usage, wrap in a coroutine
 * or background handler. Typical execution time: 5-20ms per call.
 */
object RaspNative {

    private const val TAG = "RASP_NATIVE"
    private var loaded = false

    /**
     * Load the native library. Safe to call multiple times; only loads once.
     * Returns true if the library is available, false if loading failed
     * (e.g., on x86 emulators without ARM translation).
     */
    @JvmStatic
    fun ensureLoaded(): Boolean {
        if (loaded) return true
        val isArm64 = android.os.Build.SUPPORTED_ABIS.contains("arm64-v8a")
        if (!isArm64) {
            Log.w(TAG, "Device architecture is not arm64-v8a. Bypassing native RASP load.")
            return false
        }
        return try {
            System.loadLibrary("rasp_native")
            loaded = true
            Log.i(TAG, "Native RASP library loaded successfully")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native RASP library: ${e.message}")
            Log.e(TAG, "RASP checks will be unavailable on this device/ABI")
            false
        }
    }

    // --- JNI declarations (implemented in rasp_native.cpp) ---

    /**
     * Task 1: Scan /proc/self/maps for hostile injected libraries.
     * Returns List<Map<String, String>> with keys: library, path, category.
     */
    @JvmStatic
    external fun scanProcessMaps(packageName: String): List<Map<String, String>>

    /**
     * Task 2: Verify in-memory DEX checksums against build-time hashes.
     * Returns List<String> of mismatched DEX paths (empty = clean).
     */
    @JvmStatic
    external fun verifyDexIntegrity(): List<String>

    /**
     * Task 4: Audit SIGSYS handler and measure syscall latency.
     * Returns Map with keys:
     *   hasCustomHandler (Boolean), isSuspicious (Boolean),
     *   handlerInfo (String), latencyMs (Double), seccompDetected (Boolean)
     */
    @JvmStatic
    external fun auditSigsysHandler(apkPath: String): Map<String, Any>

    /**
     * Combined RASP health check. Runs Tasks 1, 2, 4 in sequence.
     * Returns Map with keys:
     *   mapsThreats (Int), dexMismatches (Int), sigsysSuspicious (Boolean),
     *   seccompDetected (Boolean), latencyMs (Double),
     *   overallVerdict (String: "CLEAN" / "TAMPERED" / "HOSTILE")
     */
    @JvmStatic
    external fun runFullAudit(packageName: String, apkPath: String): Map<String, Any>

    // --- High-level convenience methods ---

    /**
     * Get the APK path for the current application.
     * Needed by auditSigsysHandler() and runFullAudit().
     */
    @JvmStatic
    fun getApkPath(context: Context): String {
        return try {
            context.applicationInfo.sourceDir ?: ""
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get APK path: ${e.message}")
            ""
        }
    }

    /**
     * Run the full RASP audit and return a structured result.
     * Returns null if the native library is not available.
     */
    @JvmStatic
    fun audit(context: Context): RaspAuditResult? {
        if (!ensureLoaded()) return null

        val packageName = context.packageName
        val apkPath = getApkPath(context)
        if (apkPath.isEmpty()) {
            Log.e(TAG, "Cannot determine APK path, skipping RASP audit")
            return null
        }

        return try {
            val raw = runFullAudit(packageName, apkPath)

            RaspAuditResult(
                mapsThreats = (raw["mapsThreats"] as? Number)?.toInt() ?: 0,
                dexMismatches = (raw["dexMismatches"] as? Number)?.toInt() ?: 0,
                sigsysSuspicious = raw["sigsysSuspicious"] as? Boolean ?: false,
                seccompDetected = raw["seccompDetected"] as? Boolean ?: false,
                latencyMs = (raw["latencyMs"] as? Number)?.toDouble() ?: 0.0,
                overallVerdict = raw["overallVerdict"] as? String ?: "UNKNOWN"
            )
        } catch (e: Exception) {
            Log.e(TAG, "RASP audit failed: ${e.message}", e)
            null
        }
    }
}

/**
 * Structured result from a full RASP audit.
 */
data class RaspAuditResult(
    val mapsThreats: Int,
    val dexMismatches: Int,
    val sigsysSuspicious: Boolean,
    val seccompDetected: Boolean,
    val latencyMs: Double,
    val overallVerdict: String  // "CLEAN", "TAMPERED", or "HOSTILE"
) {
    /** Convert to a Flutter-friendly channel map. */
    fun toChannelMap(): HashMap<String, Any> = hashMapOf(
        "mapsThreats" to mapsThreats,
        "dexMismatches" to dexMismatches,
        "sigsysSuspicious" to sigsysSuspicious,
        "seccompDetected" to seccompDetected,
        "latencyMs" to latencyMs,
        "overallVerdict" to overallVerdict
    )
}
