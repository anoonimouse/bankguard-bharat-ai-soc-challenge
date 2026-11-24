package com.bankguard.sdk

/**
 * Stateless risk scoring function for the behavioral engine.
 *
 * Takes a [BehavioralProfile] snapshot and produces a score (0-100)
 * and a verdict string. This is a pure calculation - no side effects,
 * no state, no I/O. Must complete in under 5ms.
 *
 * Scoring weights are fully configurable via [ScoringWeights].
 * The whitelist is checked first - whitelisted apps always score 0.
 */
class BehavioralRiskScorer(
    private val weights: ScoringWeights = ScoringWeights(),
    private val whitelist: KnownSafeWhitelist = KnownSafeWhitelist(),
    private val timeWindowManager: TimeWindowManager = TimeWindowManager()
) {
    data class ScoringResult(
        val score: Int,
        val verdict: String
    )

    fun score(profile: BehavioralProfile): ScoringResult {
        // Whitelisted apps always score 0
        if (whitelist.isSafe(profile.packageName)) {
            return ScoringResult(score = 0, verdict = VERDICT_CLEAN)
        }

        var points = 0

        // --- Base signals (additive) ---
        if (profile.installSource != InstallSource.PLAY_STORE) {
            points += weights.unknownSourceInstall
        }
        if (profile.hasBankingKeywords) {
            points += weights.bankingKeywords
        }
        if (profile.installSource == InstallSource.UNKNOWN ||
            profile.installSource == InstallSource.BROWSER ||
            profile.installSource == InstallSource.FILE_MANAGER) {
            points += weights.noPlayStoreMetadata
        }
        if (profile.smsGrantedMs > 0) {
            points += weights.smsPermission
        }
        if (profile.overlayGrantedMs > 0) {
            points += weights.overlayPermission
        }
        if (profile.accessibilityEnabledMs > 0) {
            points += weights.accessibilityEnabled
        }

        // --- Behavioral chain bonuses ---
        val installMs = profile.installTimestampMs

        // Stage 1 -> Stage 2 (install -> overlay within window)
        val s1s2 = profile.overlayGrantedMs > 0 &&
                timeWindowManager.isWithinChainWindow(installMs, profile.overlayGrantedMs)
        if (s1s2) points += weights.stage1ToStage2

        // Stage 1 -> Stage 3 (install -> accessibility within window)
        val s1s3 = profile.accessibilityEnabledMs > 0 &&
                timeWindowManager.isWithinChainWindow(installMs, profile.accessibilityEnabledMs)
        if (s1s3) points += weights.stage1ToStage3

        // Stage 2 -> Stage 3 (overlay -> accessibility within window)
        val s2s3 = profile.overlayGrantedMs > 0 && profile.accessibilityEnabledMs > 0 &&
                timeWindowManager.isWithinChainWindow(profile.overlayGrantedMs, profile.accessibilityEnabledMs)
        if (s2s3) points += weights.stage2ToStage3

        // Full chain bonus (all 3 stages within window)
        if (s1s2 && s1s3 && s2s3) {
            points += weights.fullChainBonus
        }

        // SMS + Overlay + Accessibility simultaneously
        if (profile.smsGrantedMs > 0 && profile.overlayGrantedMs > 0 && profile.accessibilityEnabledMs > 0) {
            points += weights.smsOverlayAccessibility
        }

        // --- Mitigating factors (subtractive) ---
        if (profile.installSource == InstallSource.PLAY_STORE) {
            points -= weights.playStoreInstallReduction
        }

        if (timeWindowManager.isEstablishedApp(profile.installTimestampMs)) {
            points -= weights.establishedAppReduction
        }

        // Clamp to 0-100
        points = points.coerceIn(0, 100)

        val verdict = when {
            points >= 91 -> VERDICT_CRITICAL
            points >= 76 -> VERDICT_HIGH_RISK
            points >= 51 -> VERDICT_SUSPICIOUS
            points >= 26 -> VERDICT_MONITOR
            else -> VERDICT_CLEAN
        }

        return ScoringResult(score = points, verdict = verdict)
    }

    companion object {
        const val VERDICT_CLEAN = "CLEAN"
        const val VERDICT_MONITOR = "MONITOR"
        const val VERDICT_SUSPICIOUS = "SUSPICIOUS"
        const val VERDICT_HIGH_RISK = "HIGH_RISK"
        const val VERDICT_CRITICAL = "CRITICAL"
    }
}

/**
 * Configurable scoring weights for the behavioral risk engine.
 * All values are in "points" (0-100 scale).
 */
data class ScoringWeights(
    // Base signals (additive)
    val unknownSourceInstall: Int = 15,
    val bankingKeywords: Int = 20,
    val noPlayStoreMetadata: Int = 10,
    val smsPermission: Int = 15,
    val overlayPermission: Int = 15,
    val accessibilityEnabled: Int = 15,

    // Behavioral chain bonuses
    val stage1ToStage2: Int = 25,
    val stage1ToStage3: Int = 25,
    val stage2ToStage3: Int = 30,
    val fullChainBonus: Int = 40,
    val smsOverlayAccessibility: Int = 35,

    // Mitigating factors
    val playStoreInstallReduction: Int = 30,
    val establishedAppReduction: Int = 20
)

/**
 * Known-safe app whitelist. Prefixes listed here will always score 0.
 * The host app can add custom entries at initialization time.
 */
class KnownSafeWhitelist(
    additionalPrefixes: List<String> = emptyList()
) {
    private val prefixes: List<String> = DEFAULT_PREFIXES + additionalPrefixes

    fun isSafe(packageName: String): Boolean {
        return prefixes.any { packageName.startsWith(it) }
    }

    companion object {
        val DEFAULT_PREFIXES = listOf(
            "com.google.android.",
            "com.android.",
            "com.samsung.android.",
            "com.oneplus.",
            "com.microsoft.",
            "com.lastpass.",
            "com.dashlane.",
            "com.onepassword.",
            "com.microsoft.launcher."
        )
    }
}
