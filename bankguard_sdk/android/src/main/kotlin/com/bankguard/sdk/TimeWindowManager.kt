package com.bankguard.sdk

/**
 * Temporal correlation utility for the behavioral engine.
 * Determines whether two events are close enough in time to be considered
 * part of the same attack chain.
 *
 * All time windows are configurable - no hardcoded values except defaults.
 */
class TimeWindowManager(
    /** Default chain detection window in milliseconds (default: 5 minutes). */
    var chainWindowMs: Long = 5 * 60 * 1000L,
    /** Age threshold in milliseconds after which an app is considered "established" (default: 30 days). */
    var establishedAppAgeMs: Long = 30L * 24 * 60 * 60 * 1000L,
    /** TTL for stale profiles in milliseconds (default: 24 hours). */
    var profileTtlMs: Long = 24L * 60 * 60 * 1000L
) {
    /**
     * Returns true if [eventTimestampMs] occurred within [chainWindowMs]
     * of [referenceTimestampMs]. Both must be positive.
     */
    fun isWithinChainWindow(referenceTimestampMs: Long, eventTimestampMs: Long): Boolean {
        if (referenceTimestampMs <= 0 || eventTimestampMs <= 0) return false
        return kotlin.math.abs(eventTimestampMs - referenceTimestampMs) <= chainWindowMs
    }

    /**
     * Returns true if the app was installed more than [establishedAppAgeMs] ago.
     */
    fun isEstablishedApp(installTimestampMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        if (installTimestampMs <= 0) return false
        return (nowMs - installTimestampMs) >= establishedAppAgeMs
    }

    /**
     * Returns true if the profile is stale (no updates for longer than [profileTtlMs]).
     */
    fun isProfileStale(lastUpdatedMs: Long, nowMs: Long = System.currentTimeMillis()): Boolean {
        return (nowMs - lastUpdatedMs) >= profileTtlMs
    }
}
