package com.bankguard.sdk

import org.json.JSONArray
import org.json.JSONObject

/**
 * Represents a single security-relevant event observed for an app.
 * Each event has a type, a timestamp, and an optional detail string.
 */
data class BehavioralEvent(
    val type: String,        // INSTALLED, OVERLAY_GRANTED, ACCESSIBILITY_ENABLED, SMS_GRANTED, REMOVED
    val timestampMs: Long,
    val detail: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("type", type)
        put("timestampMs", timestampMs)
        put("detail", detail)
    }

    companion object {
        fun fromJson(json: JSONObject) = BehavioralEvent(
            type = json.optString("type", ""),
            timestampMs = json.optLong("timestampMs", 0),
            detail = json.optString("detail", "")
        )

        // Event type constants
        const val INSTALLED = "INSTALLED"
        const val OVERLAY_GRANTED = "OVERLAY_GRANTED"
        const val ACCESSIBILITY_ENABLED = "ACCESSIBILITY_ENABLED"
        const val SMS_GRANTED = "SMS_GRANTED"
        const val REMOVED = "REMOVED"
    }
}

/**
 * Installation source classification for a package.
 */
enum class InstallSource(val label: String) {
    PLAY_STORE("play_store"),
    BROWSER("browser"),
    FILE_MANAGER("file_manager"),
    ADB("adb"),
    UNKNOWN("unknown");

    companion object {
        fun fromLabel(label: String): InstallSource =
            values().firstOrNull { it.label == label } ?: UNKNOWN
    }
}

/**
 * Behavioral profile for a single monitored app.
 * Tracks the app's security-relevant state over time - installation source,
 * permission acquisition timestamps, attack chain stage, and event timeline.
 *
 * This is the core data structure of the behavioral engine. The RiskScorer
 * reads these profiles to produce risk scores; the EventCollector writes to them.
 */
data class BehavioralProfile(
    val packageName: String,
    val installTimestampMs: Long,
    val installSource: InstallSource = InstallSource.UNKNOWN,
    val appLabel: String = "",
    val hasBankingKeywords: Boolean = false,

    // Permission acquisition timestamps (0 = not yet acquired)
    var overlayGrantedMs: Long = 0,
    var accessibilityEnabledMs: Long = 0,
    var smsGrantedMs: Long = 0,

    // Current attack chain stage (0 = not started, 1 = installed, 2 = overlay, 3 = accessibility)
    var currentStage: Int = 0,

    // Risk assessment
    var lastScore: Int = 0,
    var lastVerdict: String = "CLEAN",

    // Timeline of events for the audit trail
    val events: MutableList<BehavioralEvent> = mutableListOf(),

    // Whether an alert has already been fired for this profile
    var alertFired: Boolean = false,

    // Last update timestamp for TTL tracking
    var lastUpdatedMs: Long = System.currentTimeMillis()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("packageName", packageName)
        put("installTimestampMs", installTimestampMs)
        put("installSource", installSource.label)
        put("appLabel", appLabel)
        put("hasBankingKeywords", hasBankingKeywords)
        put("overlayGrantedMs", overlayGrantedMs)
        put("accessibilityEnabledMs", accessibilityEnabledMs)
        put("smsGrantedMs", smsGrantedMs)
        put("currentStage", currentStage)
        put("lastScore", lastScore)
        put("lastVerdict", lastVerdict)
        put("alertFired", alertFired)
        put("lastUpdatedMs", lastUpdatedMs)
        put("events", JSONArray().apply {
            events.forEach { put(it.toJson()) }
        })
    }

    /** Convert to a flat map for the Dart MethodChannel. */
    fun toChannelMap(): HashMap<String, Any?> = hashMapOf(
        "packageName" to packageName,
        "installTimestampMs" to installTimestampMs,
        "installSource" to installSource.label,
        "appLabel" to appLabel,
        "hasBankingKeywords" to hasBankingKeywords,
        "overlayGrantedMs" to overlayGrantedMs,
        "accessibilityEnabledMs" to accessibilityEnabledMs,
        "smsGrantedMs" to smsGrantedMs,
        "currentStage" to currentStage,
        "lastScore" to lastScore,
        "lastVerdict" to lastVerdict,
        "alertFired" to alertFired,
        "lastUpdatedMs" to lastUpdatedMs,
        "events" to events.map { e ->
            hashMapOf(
                "type" to e.type,
                "timestampMs" to e.timestampMs,
                "detail" to e.detail
            )
        }
    )

    companion object {
        fun fromJson(json: JSONObject): BehavioralProfile {
            val events = mutableListOf<BehavioralEvent>()
            val eventsArray = json.optJSONArray("events")
            if (eventsArray != null) {
                for (i in 0 until eventsArray.length()) {
                    events.add(BehavioralEvent.fromJson(eventsArray.getJSONObject(i)))
                }
            }
            return BehavioralProfile(
                packageName = json.optString("packageName", ""),
                installTimestampMs = json.optLong("installTimestampMs", 0),
                installSource = InstallSource.fromLabel(json.optString("installSource", "unknown")),
                appLabel = json.optString("appLabel", ""),
                hasBankingKeywords = json.optBoolean("hasBankingKeywords", false),
                overlayGrantedMs = json.optLong("overlayGrantedMs", 0),
                accessibilityEnabledMs = json.optLong("accessibilityEnabledMs", 0),
                smsGrantedMs = json.optLong("smsGrantedMs", 0),
                currentStage = json.optInt("currentStage", 0),
                lastScore = json.optInt("lastScore", 0),
                lastVerdict = json.optString("lastVerdict", "CLEAN"),
                alertFired = json.optBoolean("alertFired", false),
                lastUpdatedMs = json.optLong("lastUpdatedMs", System.currentTimeMillis()),
                events = events
            )
        }

        /** Banking keyword patterns for package name / app label matching. */
        val BANKING_KEYWORDS = listOf(
            "sbi", "yono", "lotusintouch", "sbifreedom", "sbionline",
            "banking", "bank", "upi", "paytm", "phonepe", "gpay"
        )

        fun containsBankingKeywords(text: String): Boolean {
            val lower = text.lowercase()
            return BANKING_KEYWORDS.any { lower.contains(it) }
        }
    }
}
