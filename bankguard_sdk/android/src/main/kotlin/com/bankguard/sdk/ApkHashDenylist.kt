package com.bankguard.sdk

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/**
 * Local APK hash denylist manager.
 *
 * Maintains a set of known-bad SHA-256 certificate hashes for installed apps.
 * The denylist is composed of two sources:
 *   1. Embedded defaults (shipped with the SDK)
 *   2. Backend-synced entries (fetched and persisted locally)
 *
 * Lookup is O(1) via HashSet. Persistence uses SharedPreferences for simplicity
 * since denylist entries are small strings (64 chars each).
 */
class ApkHashDenylist private constructor(
    private val prefs: SharedPreferences
) {
    private val denySet = mutableSetOf<String>()
    private var lastSyncTimestamp: Long = 0

    init {
        loadFromDisk()
    }

    // Embedded defaults: known malicious cert hashes discovered during testing.
    // These ship with the SDK so protection works offline from day one.
    companion object {
        private const val PREFS_NAME = "bankguard_apk_denylist"
        private const val KEY_HASHES = "denied_hashes"
        private const val KEY_LAST_SYNC = "last_sync_ms"
        private const val KEY_VERSION = "denylist_version"

        private val EMBEDDED_HASHES = setOf(
            // spoof_app cert hash (from project's own test malware)
            "SPOOF_APP_HASH_PLACEHOLDER"
        )

        @Volatile
        private var instance: ApkHashDenylist? = null

        fun getInstance(context: Context): ApkHashDenylist {
            return instance ?: synchronized(this) {
                instance ?: ApkHashDenylist(
                    context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                ).also { instance = it }
            }
        }
    }

    /**
     * Check if a certificate hash is on the denylist.
     * Normalizes input to uppercase colon-separated format before lookup.
     */
    fun isDenied(certHash: String): Boolean {
        val normalized = normalizeHash(certHash)
        return denySet.contains(normalized)
    }

    /**
     * Check if a package name is on the denylist by computing its cert hash.
     * Returns the hash if denied, null if clean or unable to compute.
     * Fail-open: returns null on any error.
     */
    fun checkPackage(context: Context, packageName: String): String? {
        return try {
            val hash = computeCertHash(context, packageName) ?: return null
            if (isDenied(hash)) hash else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Add a single hash to the denylist and persist.
     */
    fun addHash(certHash: String) {
        val normalized = normalizeHash(certHash)
        if (normalized.isNotBlank()) {
            denySet.add(normalized)
            saveToDisk()
        }
    }

    /**
     * Bulk-merge hashes from a backend sync response.
     * Expects a list of uppercase colon-separated SHA-256 strings.
     * Returns the count of newly added entries.
     */
    fun mergeFromBackend(hashes: List<String>, syncTimestamp: Long = System.currentTimeMillis()): Int {
        val before = denySet.size
        for (hash in hashes) {
            val normalized = normalizeHash(hash)
            if (normalized.isNotBlank()) {
                denySet.add(normalized)
            }
        }
        lastSyncTimestamp = syncTimestamp
        saveToDisk()
        return denySet.size - before
    }

    /**
     * Remove a hash (for false-positive correction).
     */
    fun removeHash(certHash: String) {
        denySet.remove(normalizeHash(certHash))
        saveToDisk()
    }

    /** Current denylist size (embedded + synced). */
    fun size(): Int = denySet.size

    /** Timestamp of last backend sync, or 0 if never synced. */
    fun lastSyncMs(): Long = lastSyncTimestamp

    /** Export current denylist as a JSON array for diagnostics. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("hashes", JSONArray(denySet.toList()))
        put("count", denySet.size)
        put("lastSyncMs", lastSyncTimestamp)
    }

    /** Export as a channel-friendly map for Dart bridge. */
    fun toChannelMap(): HashMap<String, Any> = hashMapOf(
        "hashes" to denySet.toList(),
        "count" to denySet.size,
        "lastSyncMs" to lastSyncTimestamp
    )

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    private fun loadFromDisk() {
        // Always start with embedded defaults
        denySet.addAll(EMBEDDED_HASHES.map { normalizeHash(it) }.filter { it.isNotBlank() })

        // Layer on synced hashes from SharedPreferences
        val stored = prefs.getString(KEY_HASHES, null)
        if (stored != null) {
            try {
                val array = JSONArray(stored)
                for (i in 0 until array.length()) {
                    val h = normalizeHash(array.optString(i, ""))
                    if (h.isNotBlank()) denySet.add(h)
                }
            } catch (_: Exception) {
                // Corrupted store; embedded defaults still active
            }
        }
        lastSyncTimestamp = prefs.getLong(KEY_LAST_SYNC, 0)
    }

    private fun saveToDisk() {
        val array = JSONArray(denySet.toList())
        prefs.edit()
            .putString(KEY_HASHES, array.toString())
            .putLong(KEY_LAST_SYNC, lastSyncTimestamp)
            .apply()
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    /** Normalize to uppercase colon-separated format: "AB:CD:EF:..." */
    private fun normalizeHash(hash: String): String {
        val cleaned = hash.uppercase().replace(Regex("[^A-F0-9]"), "")
        if (cleaned.length != 64) return cleaned.uppercase()
        return cleaned.chunked(2).joinToString(":")
    }

    /** Compute the SHA-256 cert hash for an installed package. */
    @Suppress("DEPRECATION")
    private fun computeCertHash(context: Context, packageName: String): String? {
        return try {
            val pm = context.packageManager
            val signatures = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                val pi = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                pi.signingInfo?.apkContentsSigners
            } else {
                val pi = pm.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
                pi.signatures
            }
            if (signatures.isNullOrEmpty()) return null

            val md = MessageDigest.getInstance("SHA-256")
            md.update(signatures[0].toByteArray())
            md.digest().joinToString(":") { "%02X".format(it) }
        } catch (_: Exception) {
            null
        }
    }
}
