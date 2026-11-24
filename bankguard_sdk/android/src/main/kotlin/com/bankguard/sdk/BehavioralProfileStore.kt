package com.bankguard.sdk

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONObject

/**
 * In-memory + SharedPreferences store for behavioral profiles.
 *
 * Profiles are kept in memory during the session for fast access.
 * Persistence to SharedPreferences ensures profiles survive app restarts
 * and can detect slow-moving attacks that unfold over hours.
 *
 * Bounded at [MAX_PROFILES] entries (LRU eviction).
 * Profiles older than the configured TTL are discarded on load.
 */
class BehavioralProfileStore(
    context: Context,
    private val timeWindowManager: TimeWindowManager = TimeWindowManager()
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val profiles = LinkedHashMap<String, BehavioralProfile>(
        MAX_PROFILES + 1, 0.75f, true // access-ordered for LRU eviction
    )

    init {
        loadFromDisk()
    }

    /** Get profile for a package, or null if not monitored. */
    fun get(packageName: String): BehavioralProfile? = profiles[packageName]

    /** Get all current profiles. */
    fun getAll(): List<BehavioralProfile> = profiles.values.toList()

    /** Insert or update a profile. Triggers LRU eviction if at capacity. */
    fun put(profile: BehavioralProfile) {
        profiles[profile.packageName] = profile
        evictIfNeeded()
        persistAsync()
    }

    /** Remove a profile (e.g. when app is uninstalled). */
    fun remove(packageName: String) {
        profiles.remove(packageName)
        persistAsync()
    }

    /** Clear all profiles. */
    fun clear() {
        profiles.clear()
        prefs.edit().remove(KEY_PROFILES).apply()
    }

    /** Persist current state to disk asynchronously. */
    fun persistAsync() {
        val json = JSONObject()
        for ((pkg, profile) in profiles) {
            json.put(pkg, profile.toJson())
        }
        prefs.edit().putString(KEY_PROFILES, json.toString()).apply()
    }

    /** Load profiles from disk, discarding stale entries. */
    private fun loadFromDisk() {
        val raw = prefs.getString(KEY_PROFILES, null) ?: return
        try {
            val json = JSONObject(raw)
            val now = System.currentTimeMillis()
            val keys = json.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                val profile = BehavioralProfile.fromJson(json.getJSONObject(key))
                // Discard stale profiles
                if (!timeWindowManager.isProfileStale(profile.lastUpdatedMs, now)) {
                    profiles[profile.packageName] = profile
                }
            }
        } catch (e: Exception) {
            // Corrupt data - start fresh
            prefs.edit().remove(KEY_PROFILES).apply()
        }
    }

    /** Evict the least-recently-accessed profile if at capacity. */
    private fun evictIfNeeded() {
        while (profiles.size > MAX_PROFILES) {
            val oldest = profiles.entries.iterator().next()
            profiles.remove(oldest.key)
        }
    }

    companion object {
        private const val PREFS_NAME = "bankguard_behavioral"
        private const val KEY_PROFILES = "profiles_v1"
        const val MAX_PROFILES = 50
    }
}
