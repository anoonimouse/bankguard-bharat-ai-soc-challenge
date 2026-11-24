package com.bankguard.sdk

/**
 * Social Engineering Pattern Detection Engine.
 * Detects complex manipulation patterns across 7 Indian languages (EN, HI, TA, TE, BN, MR, KN).
 * Now supports 9 categories including Authority (Digital Arrest), Utility, and Govt Schemes.
 */
class SocialEngineeringEngine {

    data class AnalysisResult(
        val categories: List<String>,
        val matchedPhrases: List<String>,
        val score: Int,
        val primaryCategory: String?,
        val verdict: String, // "none", "soft", "hard"
        val isHighSeverity: Boolean = false
    )

    companion object {
        private val urlRegex = Regex("(https?://[^\\s]+)", RegexOption.IGNORE_CASE)
        private val phoneRegex = Regex("(?:1800[- ]?\\d{3}[- ]?\\d{4})|\\b[6-9]\\d{9}\\b")
    }

    fun analyze(text: String): AnalysisResult {
        val lowerText = text.lowercase()
        var score = 0
        val categories = mutableListOf<String>()
        val matchedPhrases = mutableListOf<String>()

        val hasUrl = containsUrl(text)
        if (hasUrl) {
            score += 40
            if (ScamTriggers.bankAppKeywords.any { lowerText.contains(it) }) {
                score += 20
            }
        }

        val hasPhoneNumber = phoneRegex.containsMatchIn(text)
        if (hasPhoneNumber) {
            score += 30
        }

        // 1. APK Distribution (Fake App Sharing) - HIGHEST SEVERITY
        val apkMatches = ScamTriggers.apkDistribution.filter { lowerText.contains(it.lowercase()) }
        if (apkMatches.isNotEmpty()) {
            score += 65
            categories.add("apk_distribution")
            matchedPhrases.addAll(apkMatches)
        }

        // 2. Authority (Digital Arrest / Police) - HIGH SEVERITY
        val authorityMatches = ScamTriggers.authority.filter { lowerText.contains(it.lowercase()) }
        if (authorityMatches.isNotEmpty()) {
            score += 60
            categories.add("authority")
            matchedPhrases.addAll(authorityMatches)
        }

        // 3. Traffic Challan - HIGH SEVERITY
        val challanMatches = ScamTriggers.challan.filter { lowerText.contains(it.lowercase()) }
        if (challanMatches.isNotEmpty()) {
            score += 50
            categories.add("challan")
            matchedPhrases.addAll(challanMatches)
        }

        // 4. Domain Migration
        val migrationMatches = ScamTriggers.migration.filter { lowerText.contains(it.lowercase()) }
        if (migrationMatches.isNotEmpty()) {
            score += 45
            categories.add("migration")
            matchedPhrases.addAll(migrationMatches)
        }

        // 4b. Remote Access Social Engineering - HIGH SEVERITY
        val remoteAccessMatches = ScamTriggers.remoteAccess.filter { lowerText.contains(it.lowercase()) }
        if (remoteAccessMatches.isNotEmpty()) {
            score += 60
            categories.add("remote_access")
            matchedPhrases.addAll(remoteAccessMatches)
        }

        // 4c. Action-Based OTP Request - HIGH SEVERITY
        val otpRequestMatches = ScamTriggers.otpRequest.filter { lowerText.contains(it.lowercase()) }
        if (otpRequestMatches.isNotEmpty()) {
            score += 55
            categories.add("otp_request")
            matchedPhrases.addAll(otpRequestMatches)
        }

        // 5. Utility (Electricity)
        val utilityMatches = ScamTriggers.utility.filter { lowerText.contains(it.lowercase()) }
        if (utilityMatches.isNotEmpty()) {
            score += 40
            categories.add("utility")
            matchedPhrases.addAll(utilityMatches)
        }

        // 6. Urgency
        val urgencyMatches = ScamTriggers.urgency.filter { lowerText.contains(it.lowercase()) }
        if (urgencyMatches.isNotEmpty()) {
            score += 25
            categories.add("urgency")
            matchedPhrases.addAll(urgencyMatches)
        }

        // 7. Fear (KYC/Account)
        val fearMatches = ScamTriggers.fear.filter { lowerText.contains(it.lowercase()) }
        if (fearMatches.isNotEmpty()) {
            score += 25
            categories.add("fear")
            matchedPhrases.addAll(fearMatches)
        }

        // 8. Govt Schemes
        val schemeMatches = ScamTriggers.scheme.filter { lowerText.contains(it.lowercase()) }
        if (schemeMatches.isNotEmpty()) {
            score += 35
            categories.add("scheme")
            matchedPhrases.addAll(schemeMatches)
        }

        // 9. Opportunity (Job / Money Mule Scam)
        val opportunityMatches = ScamTriggers.opportunity.filter { lowerText.contains(it.lowercase()) }
        if (opportunityMatches.isNotEmpty()) {
            score += 45
            categories.add("opportunity")
            matchedPhrases.addAll(opportunityMatches)
        }

        // 10. Greed (Rewards)
        val greedMatches = ScamTriggers.greed.filter { lowerText.contains(it.lowercase()) }
        if (greedMatches.isNotEmpty()) {
            score += 15
            categories.add("greed")
            matchedPhrases.addAll(greedMatches)
        }

        if (categories.size >= 2) {
            score += 10
        }

        score = score.coerceAtMost(100)

        // Thresholding for High Severity
        val isHighSeverity = categories.contains("apk_distribution") ||
                             categories.contains("authority") ||
                             categories.contains("challan") ||
                             categories.contains("remote_access") ||
                             categories.contains("otp_request") ||
                             (score >= 80 && (hasUrl || hasPhoneNumber))

        val primaryCategory = when {
            categories.contains("apk_distribution") -> "apk_distribution"
            categories.contains("authority") -> "authority"
            categories.contains("challan") -> "challan"
            categories.contains("remote_access") -> "remote_access"
            categories.contains("otp_request") -> "otp_request"
            categories.contains("utility") -> "utility"
            categories.contains("migration") -> "migration"
            categories.contains("scheme") -> "scheme"
            categories.contains("fear") -> "fear"
            categories.contains("urgency") -> "urgency"
            categories.contains("opportunity") -> "opportunity"
            categories.contains("greed") -> "greed"
            hasUrl -> "url_only"
            hasPhoneNumber -> "phone_only"
            else -> null
        }

        val verdict = when {
            score >= 61 || isHighSeverity -> "hard"
            score >= 31 -> "soft"
            else -> "none"
        }

        return AnalysisResult(
            categories = categories,
            matchedPhrases = matchedPhrases,
            score = score,
            primaryCategory = primaryCategory,
            verdict = verdict,
            isHighSeverity = isHighSeverity
        )
    }

    private fun containsUrl(text: String): Boolean {
        val lower = text.lowercase()
        val standardRegex = Regex("(https?:\\/\\/[^\\s]+)", RegexOption.IGNORE_CASE)
        if (standardRegex.containsMatchIn(text)) return true

        // Obfuscated URL checks (spaces, asterisks)
        val obfuscatedPatterns = listOf(
            "http ://", "https ://", "http: //", "https: //", "http : / /", "https : / /",
            "h t t p :", "h t t p s :", "w w w ."
        )
        if (obfuscatedPatterns.any { lower.contains(it) }) return true

        val domainRegex = Regex("[a-z0-9\\-]+?\\s*\\.\\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co)\\b")
        return domainRegex.containsMatchIn(lower)
    }
}
