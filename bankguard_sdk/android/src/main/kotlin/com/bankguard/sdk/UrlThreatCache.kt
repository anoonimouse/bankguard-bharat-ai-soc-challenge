package com.bankguard.sdk

import java.util.concurrent.ConcurrentHashMap

/**
 * Thread-safe process-wide cache to store URL safety verdicts.
 * Enables zero-latency link interception checks if the link was previously received in a notification.
 */
object UrlThreatCache {
    // Maps URL to safety verdict (true = safe, false = malicious)
    private val cache = ConcurrentHashMap<String, Boolean>()

    /**
     * Put a validation result into the cache.
     */
    fun put(url: String, isSafe: Boolean) {
        cache[url] = isSafe
    }

    /**
     * Get a validation result from the cache.
     * Returns null on cache miss.
     */
    fun get(url: String): Boolean? {
        return cache[url]
    }

    /**
     * Clear the cache.
     */
    fun clear() {
        cache.clear()
    }
}
