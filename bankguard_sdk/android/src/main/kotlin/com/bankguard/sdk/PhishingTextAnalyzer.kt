package com.bankguard.sdk

/**
 * Analyzer contract for mobile phishing NLP.
 *
 * This lets the notification flow stay stable while the implementation can be
 * swapped between a test double, a heuristic baseline, or a real on-device model.
 */
interface PhishingTextAnalyzer {
    data class Indicator(
        val name: String,
        val detected: Boolean,
        val evidence: String? = null,
    )

    data class AnalysisResult(
        val modelName: String,
        val phishingConfidence: Double,
        val verdict: String,
        val indicators: List<Indicator>,
    )

    fun analyze(text: String): AnalysisResult
}
