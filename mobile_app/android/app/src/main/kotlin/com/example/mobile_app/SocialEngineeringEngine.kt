package com.example.mobile_app

/**
 * Social Engineering Pattern Detection Engine
 * Detects urgency, fear, and greed manipulation patterns in notification text
 * across 6 Indian languages (EN, HI, TA, TE, BN, MR).
 */
class SocialEngineeringEngine {

    data class AnalysisResult(
        val categories: List<String>,
        val matchedPhrases: List<String>,
        val score: Int,
        val primaryCategory: String?,
        val verdict: String // "none", "soft", "hard"
    )

    companion object {
        // SBI-related keywords for URL context scoring
        private val sbiKeywords = listOf(
            "sbi", "yono", "lotusintouch", "sbifreedom", "sbionline", "sbianywhere"
        )

        private val urgencyTriggers = listOf(
            // English
            "account will be blocked", "expires in 24 hours", "immediate action required",
            "last warning", "suspended", "restricted", "verify immediately", "action required",
            "will be deactivated", "final notice", "urgent", "expiring soon", "within 24 hours",
            "account suspended", "immediately", "right away",
            // Hindi
            "अभी अपडेट करें", "तुरंत करें", "खाता बंद हो जाएगा", "24 घंटे में",
            "अंतिम चेतावनी", "तत्काल", "खाता निलंबित",
            // Tamil
            "உடனே செய்யுங்கள்", "கணக்கு தடுக்கப்படும்", "உடனடி நடவடிக்கை",
            "கடைசி எச்சரிக்கை", "இடைநிறுத்தப்பட்டது",
            // Telugu
            "వెంటనే చేయండి", "ఖాతా బ్లాక్ అవుతుంది", "తక్షణ చర్య",
            "చివరి హెచ్చరిక", "సస్పెండ్ చేయబడింది",
            // Bengali
            "এখনই করুন", "অ্যাকাউন্ট বন্ধ হবে", "তাৎক্ষণিক পদক্ষেপ",
            "শেষ সতর্কতা", "স্থগিত করা হয়েছে",
            // Marathi
            "ताबडतोब करा", "खाते बंद होईल", "तातडीची कारवाई",
            "शेवटची सूचना", "निलंबित केले"
        )

        private val fearTriggers = listOf(
            // English
            "kyc expired", "kyc expiry", "unauthorized transaction", "suspicious activity",
            "account compromised", "fraud detected", "debit card blocked", "security breach",
            "unusual login", "account at risk", "verify your identity", "otp", "credentials",
            "your account has been", "security alert", "blocked",
            // Hindi
            "केवाईसी समाप्त", "अनधिकृत लेनदेन", "संदिग्ध गतिविधि",
            "खाता खतरे में", "धोखाधड़ी का पता चला", "डेबिट कार्ड ब्लॉक",
            "सुरक्षा उल्लंघन", "केवाईसी अपडेट करें",
            // Tamil
            "கேஒய்சி காலாவதி", "அங்கீகரிக்கப்படாத பரிவர்த்தனை",
            "சந்தேகாஸ்பத செயல்பாடு", "கணக்கு ஆபத்தில்", "மோசடி கண்டறியப்பட்டது",
            // Telugu
            "కేవైసీ గడువు తీరింది", "అనధికార లావాదేవీ",
            "అనుమానాస్పద కార్యకలాపం", "ఖాతా ప్రమాదంలో", "మోసం గుర్తించబడింది",
            // Bengali
            "কেওয়াইসি মেয়াদ শেষ", "অননুমোদিত লেনদেন",
            "সন্দেহজনক কার্যকলাপ", "অ্যাকাউন্ট ঝুঁকিতে", "জালিয়াতি সনাক্ত",
            // Marathi
            "केवायसी कालबाह्य", "अनधिकृत व्यवहार",
            "संशयास्पद क्रियाकलाप", "खाते धोक्यात", "फसवणूक आढळली"
        )

        private val greedTriggers = listOf(
            // English
            "unclaimed rewards", "cashback credited", "you have won", "festival bonus",
            "reward points expiring", "lucky winner", "congratulations", "prize", "free",
            "offer expires", "claim now", "selected for", "bonus credited", "special offer",
            "redeem now", "gift", "won a", "eligible for",
            // Hindi
            "पुरस्कार", "कैशबैक", "आपने जीता", "त्योहार बोनस",
            "रिवॉर्ड पॉइंट", "भाग्यशाली विजेता", "बधाई हो", "मुफ्त",
            "इनाम", "चुने गए हैं",
            // Tamil
            "வெகுமதி", "கேஷ்பேக்", "நீங்கள் வென்றீர்கள்", "திருவிழா போனஸ்",
            "வாழ்த்துக்கள்", "இலவசம்", "பரிசு", "தேர்ந்தெடுக்கப்பட்டீர்கள்",
            // Telugu
            "బహుమతి", "క్యాష్బ్యాక్", "మీరు గెలిచారు", "పండుగ బోనస్",
            "అభినందనలు", "ఉచితం", "బహుమానం", "ఎంపిక చేయబడ్డారు",
            // Bengali
            "পুরস্কার", "ক্যাশব্যাক", "আপনি জিতেছেন", "উৎসব বোনাস",
            "অভিনন্দন", "বিনামূল্যে", "পুরস্কার", "নির্বাচিত হয়েছেন",
            // Marathi
            "बक्षीस", "कॅशबॅक", "तुम्ही जिंकलात", "सण बोनस",
            "अभिनंदन", "मोफत", "पारितोषिक", "निवडले गेले"
        )

        private val urlRegex = Regex("(https?://[^\\s]+)", RegexOption.IGNORE_CASE)
    }

    fun analyze(text: String): AnalysisResult {
        val lowerText = text.lowercase()
        var score = 0
        val categories = mutableListOf<String>()
        val matchedPhrases = mutableListOf<String>()
        val categoryScores = mutableMapOf<String, Int>()

        // URL detection
        val hasUrl = urlRegex.containsMatchIn(text)
        if (hasUrl) {
            score += 40
            val hasSbiUrl = sbiKeywords.any { lowerText.contains(it) }
            if (hasSbiUrl) {
                score += 20
            }
        }

        // Urgency triggers
        val urgencyMatches = urgencyTriggers.filter { lowerText.contains(it.lowercase()) }
        if (urgencyMatches.isNotEmpty()) {
            score += 20
            categories.add("urgency")
            matchedPhrases.addAll(urgencyMatches)
            categoryScores["urgency"] = 20
        }

        // Fear triggers
        val fearMatches = fearTriggers.filter { lowerText.contains(it.lowercase()) }
        if (fearMatches.isNotEmpty()) {
            score += 20
            categories.add("fear")
            matchedPhrases.addAll(fearMatches)
            categoryScores["fear"] = 20
        }

        // Greed triggers
        val greedMatches = greedTriggers.filter { lowerText.contains(it.lowercase()) }
        if (greedMatches.isNotEmpty()) {
            score += 15
            categories.add("greed")
            matchedPhrases.addAll(greedMatches)
            categoryScores["greed"] = 15
        }

        // Multi-category bonus
        if (categories.size >= 2) {
            score += 10
        }

        // Cap at 100
        score = score.coerceAtMost(100)

        // Determine primary category by priority: urgency > fear > greed
        val primaryCategory = when {
            categories.contains("urgency") -> "urgency"
            categories.contains("fear") -> "fear"
            categories.contains("greed") -> "greed"
            hasUrl -> "url_only"
            else -> null
        }

        // Verdict
        val verdict = when {
            score >= 61 -> "hard"
            score >= 31 -> "soft"
            else -> "none"
        }

        return AnalysisResult(
            categories = categories,
            matchedPhrases = matchedPhrases,
            score = score,
            primaryCategory = primaryCategory,
            verdict = verdict
        )
    }
}
