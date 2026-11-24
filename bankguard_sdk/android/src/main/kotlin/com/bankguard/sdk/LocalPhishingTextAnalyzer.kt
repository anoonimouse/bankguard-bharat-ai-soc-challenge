package com.bankguard.sdk

import android.content.Context
import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession
import java.nio.LongBuffer
import kotlin.math.exp
import kotlin.math.min

/**
 * On-device phishing text analyzer using a quantized TinyBERT model.
 *
 * Runs local inference on the notification message text using ONNX Runtime Mobile
 * and outputs the threat probability, indicators, and soft/hard threat verdicts.
 */
class LocalPhishingTextAnalyzer(private val context: Context) : PhishingTextAnalyzer {

    private val modelName = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
    private var env: OrtEnvironment? = null
    private var session: OrtSession? = null
    private var tokenizer: WordPieceTokenizer? = null
    private var isModelLoaded = false

    init {
        try {
            env = OrtEnvironment.getEnvironment()
            val modelBytes = context.assets.open("model_quantized.onnx").readBytes()
            session = env?.createSession(modelBytes)
            tokenizer = WordPieceTokenizer(context)
            isModelLoaded = true
            android.util.Log.i("BANKGUARD_NLP", "ONNX Runtime model and tokenizer loaded successfully from assets.")
        } catch (e: Exception) {
            isModelLoaded = false
            android.util.Log.e("BANKGUARD_NLP", "Failed to initialize ONNX Runtime session: ${e.message}")
        }
    }

    override fun analyze(text: String): PhishingTextAnalyzer.AnalysisResult {
        val lowerText = text.lowercase()

        val patterns = listOf(
            Triple("banking_impersonation", listOf("sbi", "yono", "bank", "account", "debit card", "credit card"), "banking vocabulary"),
            Triple("urgency_language", listOf("urgent", "immediately", "within 24 hours", "last warning", "final notice", "block", "expire"), "urgency cues"),
            Triple("reward_scam", listOf("reward", "gift", "prize", "cashback", "winner", "redeem"), "reward bait"),
            Triple("kyc_scam", listOf("kyc", "pan", "re-kyc", "update kyc", "verify kyc"), "kyc wording"),
            Triple("government_impersonation", listOf("cbi", "police", "government", "income tax", "rbi", "court", "digital arrest"), "official impersonation"),
            Triple("credential_theft", listOf("otp", "password", "pin", "cvv", "login", "share your code", "account details"), "credential request"),
        )

        // 1. Transactional & OTP whitelist override
        if (isLegitimateNotification(lowerText)) {
            val indicators = patterns.map { (name, _, evidence) ->
                PhishingTextAnalyzer.Indicator(name = name, detected = false, evidence = evidence)
            }
            return PhishingTextAnalyzer.AnalysisResult(
                modelName = modelName,
                phishingConfidence = 0.0,
                verdict = "none",
                indicators = indicators
            )
        }

        // Run local heuristics to extract indicators
        val indicators = patterns.map { (name, keywords, evidence) ->
            val hit = keywords.firstOrNull { keyword -> lowerText.contains(keyword) }
            PhishingTextAnalyzer.Indicator(name = name, detected = hit != null, evidence = hit ?: evidence)
        }.toMutableList()

        val hasStandardUrl = Regex("https?://[^\\s]+", RegexOption.IGNORE_CASE).containsMatchIn(text)
        val domainRegex = Regex("[a-z0-9\\-]+?\\s*\\.\\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co)\\b", RegexOption.IGNORE_CASE)
        val hasBareDomain = domainRegex.containsMatchIn(lowerText)
        if (hasStandardUrl || hasBareDomain) {
            indicators.add(PhishingTextAnalyzer.Indicator(name = "contains_url", detected = true, evidence = "url present"))
        }

        var confidence = 0.0

        // 2. Perform ONNX inference if model is loaded successfully
        if (isModelLoaded && env != null && session != null && tokenizer != null) {
            try {
                val (inputIds, attentionMask) = tokenizer!!.tokenize(lowerText)
                
                val shape = longArrayOf(1, 128)
                // token_type_ids is all zeros for single-sentence classification (sentence A only)
                val tokenTypeIds = LongArray(128) { 0L }
                val inputIdsTensor = OnnxTensor.createTensor(env!!, LongBuffer.wrap(inputIds), shape)
                val attentionMaskTensor = OnnxTensor.createTensor(env!!, LongBuffer.wrap(attentionMask), shape)
                val tokenTypeIdsTensor = OnnxTensor.createTensor(env!!, LongBuffer.wrap(tokenTypeIds), shape)

                val inputs = mapOf(
                    "input_ids" to inputIdsTensor,
                    "attention_mask" to attentionMaskTensor,
                    "token_type_ids" to tokenTypeIdsTensor
                )

                session!!.run(inputs).use { results ->
                    @Suppress("UNCHECKED_CAST")
                    val output = results.get(0).value as Array<FloatArray>
                    val logits = output[0] // shape [2]: [logit_safe, logit_phishing]
                    
                    val maxLogit = maxOf(logits[0], logits[1])
                    val exp0 = exp(logits[0] - maxLogit)
                    val exp1 = exp(logits[1] - maxLogit)
                    confidence = (exp1 / (exp0 + exp1)).toDouble()
                }
            } catch (e: Exception) {
                android.util.Log.e("BANKGUARD_NLP", "ONNX Inference failed: ${e.message}. Falling back to lexical weights.")
                confidence = computeFallbackConfidence(indicators)
            }
        } else {
            confidence = computeFallbackConfidence(indicators)
        }

        val verdict = when {
            confidence >= 0.85 -> "hard"
            confidence >= 0.50 -> "soft"
            else -> "none"
        }

        return PhishingTextAnalyzer.AnalysisResult(
            modelName = modelName,
            phishingConfidence = confidence,
            verdict = verdict,
            indicators = indicators,
        )
    }

    private fun isLegitimateNotification(text: String): Boolean {
        // Clean transaction alerts (credit/debit)
        val transactionPatterns = listOf(
            "credited to a/c", "credited to account", "credited with", "credited by rs",
            "debited from a/c", "debited from account", "debited by rs", "debited for rs",
            "transaction of rs", "available balance", "avl bal", "balance in your account",
            "salary credit", "salary credited", "payment received", "spent on your card",
            "txn of rs", "credited with rs", "debited with rs", "available limit", "avl limit",
            "का क्रेडिट", "का डेबिट", "जमा केले", "खात्यात जमा", "பற்று வைக்கப்பட்டது", "வரவு வைக்கப்பட்டது"
        )
        val hasTransactionPhrase = transactionPatterns.any { text.contains(it) }

        // Clean OTP notifications (containing OTP pattern but no threats)
        val otpKeywords = listOf(
            "otp", "code", "one time password", "one-time password is",
            "verification code", "login code", "security code is", "உங்களுக்கான otp",
            "ஒடிபி", "ஓடிபி", "ओटीपी", "கடவுச்சொல்"
        )
        val containsOtpPhrase = otpKeywords.any { text.contains(it) }
        val containsDigits = text.contains(Regex("\\b\\d{4,6}\\b"))
        val hasOtpPattern = containsOtpPhrase && containsDigits

        // Exclude threat-associated words to avoid bypass
        val threatKeywords = listOf(
            "block", "suspend", "expire", "pan card", "kyc", "verify",
            "deactivate", "cancel", "immediately", "urgent", "तत्काल", "நிறுத்தப்பட்டது"
        )
        val hasThreatKeyword = threatKeywords.any { text.contains(it) }
        
        // Exclude suspicious URLs
        val safeDomains = listOf(
            "onlinesbi.sbi", "sbi.co.in", "bank.sbi", "sbi.bank.in", "pnbindia.in", "netpnb.com", "pnb.bank.in",
            "bankofbaroda.in", "bankofbaroda.co.in", "bankofbaroda.bank.in", "bobworld.com", "bobworld.in",
            "canarabank.com", "canarabank.bank.in", "unionbankofindia.co.in", "unionbankofindia.bank.in",
            "bankofindia.co.in", "bankofindia.bank.in", "indianbank.in", "indianbank.bank.in",
            "centralbankofindia.co.in", "centralbank.bank.in", "iob.in", "iob.bank.in", "ucobank.com",
            "uco.bank.in", "bankofmaharashtra.in", "bankofmaharashtra.bank.in", "psbindia.com",
            "punjabandsind.bank.in", "idbibank.in", "idbi.bank.in", "hdfcbank.com", "hdfc.bank.in",
            "icicibank.com", "icici.bank.in", "axisbank.com", "axisbank.bank.in", "kotak.com",
            "kotak.bank.in", "indusind.com", "indusind.bank.in", "idfcfirstbank.com", "idfcfirst.bank.in",
            "yesbank.in", "yesbank.co.in", "federalbank.co.in", "federal.bank.in", "southindianbank.com",
            "rblbank.com", "rbl.bank.in", "kvb.co.in", "kvb.bank.in", "dcbbank.com", "cityunionbank.com",
            "cityunionbank.in", "karnatakabank.com", "karnatakabank.bank.in", "tmb.in", "tmb.bank.in",
            "csb.co.in", "csb.bank.in", "dhanbank.com", "dhan.bank.in", "dhanlaxmibank.com", "jkbank.com",
            "jkbank.net", "bandhanbank.com", "nainitalbank.co.in", "capitalsfb.com", "esafbank.com",
            "suryodaybank.com", "utkarshsfb.in", "sliceit.com", "janabank.com", "shivalikbank.com",
            "unitybank.co.in", "paytmbank.com", "airtelbank.com", "ippbonline.com", "ippbonline.net",
            "finobank.com", "nsdlbank.com", "jiopaymentsbank.com", "aubank.in", "equitasbank.com",
            "equitas.bank.in", "ujjivansfb.in", "ujjivansfb.bank.in", "sc.com", "sc.bank.in",
            "hsbc.co.in", "hsbc.bank.in", "citibank.co.in", "citi.bank.in", "deutschebank.co.in",
            "deutsche.bank.in", "npci.org.in", "upi.org.in", "upichalega.com", "sbicard.com",
            "sbilife.co.in", "sbimf.com", "sbismart.com", "sbigeneral.in", "hdfcbk.io",
            "hdfcbankmarks.com", "hdfcbank.net", "hdfcergo.com", "hdfclife.com", "hdfcsec.com",
            "hdfcfund.com", "icici.im", "icicipruamc.com", "iciciprudirect.com", "iciciprulife.com",
            "icicilombard.com", "axisbank.co.in", "axisdirect.in", "maxlifeinsurance.com", "axismf.com",
            "paytm.in", "paytmmoney.com", "bajajfinserv.in", "play.google.com", "google.com",
            "api.doy.codes", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "parivahan.gov.in",
            "passportindia.gov.in", "digilocker.gov.in", "cbsl.gov.in", "phonepe.com", "phonepe.in",
            "gpay.app.goo.gl", "goo.gl", "jio.com", "airtel.in", "airtel.com", "myvi.in", "bsnl.co.in",
            "mahadiscom.in", "bescom.karnataka.gov.in", "uppcl.org", "amazon.in", "amazon.com",
            "flipkart.com", "swiggy.com", "zomato.com", "indiapost.gov.in", "youtube.com",
            "wikipedia.org", "whatsapp.com"
        )
        val domainRegex = Regex("[a-z0-9\\-]+?\\s*\\.\\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co)\\b", RegexOption.IGNORE_CASE)
        val hasUrlText = text.contains("http") || domainRegex.containsMatchIn(text)
        val hasSuspiciousUrl = hasUrlText && safeDomains.none { text.contains(it) }

        return (hasTransactionPhrase || hasOtpPattern) && !hasThreatKeyword && !hasSuspiciousUrl
    }

    private fun computeFallbackConfidence(indicators: List<PhishingTextAnalyzer.Indicator>): Double {
        val weights = mapOf(
            "credential_theft" to 0.28,
            "government_impersonation" to 0.26,
            "kyc_scam" to 0.24,
            "urgency_language" to 0.18,
            "banking_impersonation" to 0.20,
            "reward_scam" to 0.14,
            "contains_url" to 0.08,
        )
        var score = 0.0
        for (indicator in indicators) {
            if (indicator.detected) {
                score += weights[indicator.name] ?: 0.05
            }
        }
        return min(score, 0.95)
    }
}
