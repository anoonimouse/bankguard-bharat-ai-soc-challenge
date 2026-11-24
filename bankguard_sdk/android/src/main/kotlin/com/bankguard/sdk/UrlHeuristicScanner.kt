package com.bankguard.sdk

import android.net.Uri
import android.util.Log

/**
 * Layer 1B: Local on-device URL phishing heuristic scanner.
 *
 * Performs fast, offline analysis of URLs without backend connectivity.
 * Each heuristic contributes a weighted score; the aggregate determines
 * the verdict. Designed to complement the backend ML classifier.
 *
 * Fail-open: all parsing and checks are try-catch guarded.
 * False positive mitigation: official domain whitelist (by registrable
 * domain, not exact subdomain) prevents legitimate SBI/YONO URLs from
 * being flagged.
 *
 * v1.2.0 CHANGES (vs v1.1.0):
 *  - Brand impersonation no longer uses naive substring matching
 *    (which let close clones like "0nlinesbi-secure.in" or
 *    "statebank-india-login.com" through while over-flagging unrelated
 *    domains that merely contained "sbi"). Now uses Levenshtein edit
 *    distance against real official brand domains, same approach as
 *    the backend ML pipeline's levenshtein_sbi / levenshtein_yono
 *    features, so on-device and backend reasoning stay conceptually
 *    aligned.
 *  - Homoglyph detection now normalizes the host (mapping confusable
 *    chars back to ASCII) and re-runs brand similarity on the
 *    normalized form, instead of just flagging "contains a confusable
 *    character" with no brand context. This stops false positives on
 *    legitimately non-English domains and catches homoglyph clones
 *    (e.g. "оnlinesbi.com" with Cyrillic о) that v1.1.0 missed.
 *  - Path keyword scoring (login/verify/kyc/...) now only contributes
 *    when there is already brand relevance on the host. Standalone,
 *    these words appear constantly on harmless URLs (news, blogs,
 *    docs) and were a major source of false positives.
 *  - Final verdict is now gated: a set of weak/generic signals alone
 *    (TLD, length, port, subdomain depth) can no longer stack into a
 *    "hard" or "soft" verdict without at least one structurally
 *    meaningful signal (brand impersonation, homoglyph-brand
 *    impersonation, IP-literal host, or known shortener).
 *  - Whitelist trimmed to registrable domains only; subdomains are
 *    covered automatically via endsWith(".$domain"), so SBI adding a
 *    new legitimate subdomain doesn't require a code change.
 */
class UrlHeuristicScanner {

    companion object {
        private const val TAG = "BG_UrlScanner"

        // Aggregate score thresholds
        private const val THRESHOLD_SOFT = 35
        private const val THRESHOLD_HARD = 60

        // Levenshtein distance window for "close clone" brand detection.
        // dist == 0 is an exact match (already caught by whitelist).
        // dist 1-3 is the classic typosquat/clone range (one or two
        // character swaps, insertions, or deletions).
        private const val BRAND_DIST_MAX = 3
    }

    // Official registrable domains. Subdomains are matched via endsWith,
    // so do NOT need to (and should not) list every subdomain here —
    // that was dead weight in v1.1.0 and a maintenance trap.
    private val officialDomains = setOf(
        "onlinesbi.sbi",
        "sbi.co.in",
        "bank.sbi",
        "sbi.bank.in",
        "pnbindia.in",
        "netpnb.com",
        "pnb.bank.in",
        "bankofbaroda.in",
        "bankofbaroda.co.in",
        "bankofbaroda.bank.in",
        "bobworld.com",
        "bobworld.in",
        "canarabank.com",
        "canarabank.bank.in",
        "unionbankofindia.co.in",
        "unionbankofindia.bank.in",
        "bankofindia.co.in",
        "bankofindia.bank.in",
        "indianbank.in",
        "indianbank.bank.in",
        "centralbankofindia.co.in",
        "centralbank.bank.in",
        "iob.in",
        "iob.bank.in",
        "ucobank.com",
        "uco.bank.in",
        "bankofmaharashtra.in",
        "bankofmaharashtra.bank.in",
        "psbindia.com",
        "punjabandsind.bank.in",
        "idbibank.in",
        "idbi.bank.in",
        "hdfcbank.com",
        "hdfc.bank.in",
        "icicibank.com",
        "icici.bank.in",
        "axisbank.com",
        "axisbank.bank.in",
        "kotak.com",
        "kotak.bank.in",
        "indusind.com",
        "indusind.bank.in",
        "idfcfirstbank.com",
        "idfcfirst.bank.in",
        "yesbank.in",
        "yesbank.co.in",
        "federalbank.co.in",
        "federal.bank.in",
        "southindianbank.com",
        "rblbank.com",
        "rbl.bank.in",
        "kvb.co.in",
        "kvb.bank.in",
        "dcbbank.com",
        "cityunionbank.com",
        "cityunionbank.in",
        "karnatakabank.com",
        "karnatakabank.bank.in",
        "tmb.in",
        "tmb.bank.in",
        "csb.co.in",
        "csb.bank.in",
        "dhanbank.com",
        "dhan.bank.in",
        "dhanlaxmibank.com",
        "jkbank.com",
        "jkbank.net",
        "bandhanbank.com",
        "nainitalbank.co.in",
        "capitalsfb.com",
        "esafbank.com",
        "suryodaybank.com",
        "utkarshsfb.in",
        "sliceit.com",
        "janabank.com",
        "shivalikbank.com",
        "unitybank.co.in",
        "paytmbank.com",
        "airtelbank.com",
        "ippbonline.com",
        "ippbonline.net",
        "finobank.com",
        "nsdlbank.com",
        "jiopaymentsbank.com",
        "aubank.in",
        "equitasbank.com",
        "equitas.bank.in",
        "ujjivansfb.in",
        "ujjivansfb.bank.in",
        "sc.com",
        "sc.bank.in",
        "hsbc.co.in",
        "hsbc.bank.in",
        "citibank.co.in",
        "citi.bank.in",
        "deutschebank.co.in",
        "deutsche.bank.in",
        "npci.org.in",
        "upi.org.in",
        "upichalega.com",
        "sbicard.com",
        "sbilife.co.in",
        "sbimf.com",
        "sbismart.com",
        "sbigeneral.in",
        "hdfcbk.io",
        "hdfcbankmarks.com",
        "hdfcbank.net",
        "hdfcergo.com",
        "hdfclife.com",
        "hdfcsec.com",
        "hdfcfund.com",
        "icici.im",
        "icicipruamc.com",
        "iciciprudirect.com",
        "iciciprulife.com",
        "icicilombard.com",
        "axisbank.co.in",
        "axisdirect.in",
        "maxlifeinsurance.com",
        "axismf.com",
        "paytm.in",
        "paytmmoney.com",
        "bajajfinserv.in",
        "play.google.com",
        "google.com",
        "api.doy.codes"
    )

    // Global trusted domains that bypass validation instantly to eliminate latency for standard web use.
    private val globalSafeDomains = setOf(
        "youtube.com", "youtu.be", "wikipedia.org", "github.com", "whatsapp.com",
        "wa.me", "facebook.com", "instagram.com", "linkedin.com", "twitter.com",
        "x.com", "amazon.in", "amazon.com", "flipkart.com", "pinterest.com",
        "reddit.com", "netflix.com", "spotify.com", "zoom.us", "slack.com",
        "microsoft.com", "apple.com",
        // Government & Identity Services
        "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in", "parivahan.gov.in",
        "passportindia.gov.in", "digilocker.gov.in", "cbsl.gov.in",
        // Payments & Telecom
        "npci.org.in", "paytm.com", "phonepe.com", "gpay.app.goo.gl", "goo.gl", "jio.com",
        "airtel.in", "myvi.in", "bsnl.co.in", "airtel.com", "phonepe.in",
        // Utilities & E-commerce
        "mahadiscom.in", "bescom.karnataka.gov.in", "uppcl.org",
        "swiggy.com", "zomato.com", "indiapost.gov.in", "amazon.in", "flipkart.com"
    )

    // Official brand "core" strings used for Levenshtein comparison.
    // These are the registrable-domain labels (without TLD) of real
    // SBI/YONO properties — i.e. what a clone is actually trying to
    // imitate. Keep this list narrow and high-confidence; it directly
    // drives the strongest scoring signal in the scanner.
    private val officialBrandCores = setOf(
        "sbi", "onlinesbi", "yono", "yonosbi",
        "hdfc", "hdfcbank", "payzapp",
        "icici", "icicibank", "imobile",
        "axis", "axisbank", "axismobile",
        "kotak", "kotakbank", "kotak811",
        "pnb", "pnbone",
        "bankofbaroda", "bobworld", "bob",
        "canara", "canarabank", "candi",
        "unionbank", "unionvyom",
        "indusind", "indusmobile",
        "idfcfirst", "idfcfirstbank",
        "federalbank", "fedmobile",
        "yesbank", "yesmobile",
        "bankofmaharashtra", "mahamobile",
        "idbi", "idbibank",
        "southindianbank", "sibmirror",
        "rblbank", "rblmobank",
        "paytm", "paytmbank",
        "airtel", "airtelbank", "airtelthanks",
        "indiapost", "ippb",
        "au", "aubank",
        "equitas", "ujjivan",
        "npci", "bhim", "upi"
    )

    // TLDs commonly abused in phishing campaigns
    private val suspiciousTlds = setOf(
        ".xyz", ".top", ".club", ".work", ".buzz",
        ".info", ".tk", ".ml", ".ga", ".cf",
        ".gq", ".icu", ".site", ".online", ".fun",
        ".live", ".click", ".link", ".space", ".store",
        ".stream", ".download", ".win", ".bid", ".racing"
    )

    // Known URL shortener domains
    private val shortenerDomains = setOf(
        "bit.ly", "tinyurl.com", "t.co", "goo.gl",
        "is.gd", "cli.gs", "ow.ly", "surl.li",
        "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
        "tiny.cc", "v.gd", "clck.ru", "lnkd.in"
    )

    // Homoglyphs: characters that visually mimic standard ASCII letters.
    // Used to NORMALIZE the host before brand comparison — not as a
    // standalone scoring signal anymore.
    private val homoglyphMap = mapOf(
        'а' to 'a', // Cyrillic a
        'е' to 'e', // Cyrillic e
        'о' to 'o', // Cyrillic o
        'р' to 'p', // Cyrillic p
        'с' to 'c', // Cyrillic c
        'ı' to 'i', // Turkish dotless i
        'ɡ' to 'g', // IPA g
        'ν' to 'v', // Greek nu
        'ⅰ' to 'i', // Roman numeral
        '0' to 'o'  // Zero for o
    )

    // Signals that, on their own, are considered strong enough evidence
    // to allow escalation to soft/hard. Generic/weak signals (TLD,
    // length, port, subdomain depth, path keywords without brand
    // relevance) cannot reach a verdict by themselves — see gating
    // logic in performScan().
    private val strongSignalFlags = setOf(
        "BRAND_IMPERSONATION",
        "HOMOGLYPH_BRAND_IMPERSONATION",
        "IP_BASED_HOST",
        "URL_SHORTENER"
    )

    /**
     * Scan a single URL and return the heuristic result.
     * Thread-safe, no side effects.
     */
    fun scan(url: String): ScanResult {
        return try {
            performScan(url)
        } catch (e: Exception) {
            Log.w(TAG, "Scan failed for URL, failing open: ${e.message}")
            ScanResult(
                url = url,
                score = 0,
                verdict = "none",
                flags = emptyList(),
                isSafe = true
            )
        }
    }

    /**
     * Extract all URLs from text and scan each one.
     * Returns results only for flagged URLs (soft or hard verdict).
     */
    fun scanText(text: String): List<ScanResult> {
        val urlPattern = Regex("(https?://[^\\s\"'<>]+)", RegexOption.IGNORE_CASE)
        val urls = urlPattern.findAll(text).map { it.value }.toList()
        return urls.mapNotNull { url ->
            val result = scan(url)
            if (result.verdict != "none") result else null
        }
    }

    private fun performScan(rawUrl: String): ScanResult {
        val url = rawUrl.trim()
        val uri = try {
            Uri.parse(url)
        } catch (e: Exception) {
            return ScanResult(url = url, score = 0, verdict = "none",
                flags = emptyList(), isSafe = true)
        }

        val host = uri.host?.lowercase()?.trim()?.removeSuffix(".") ?: ""
        val path = uri.path?.lowercase() ?: ""
        val fullUrl = url.lowercase()

        // Whitelist check — official domains and global safe domains (and any subdomain of them)
        // are always safe. This must run before any scoring.
        if (officialDomains.any { host == it || host.endsWith(".$it") } ||
            globalSafeDomains.any { host == it || host.endsWith(".$it") }) {
            return ScanResult(url = url, score = 0, verdict = "none",
                flags = emptyList(), isSafe = true)
        }

        var score = 0
        val flags = mutableListOf<String>()

        // H1: IP-based host (e.g. http://192.168.1.1/sbi-login)
        if (isIpAddress(host)) {
            score += 30
            flags.add("IP_BASED_HOST")
        }

        // H2: Suspicious TLD
        if (suspiciousTlds.any { host.endsWith(it) }) {
            score += 20
            flags.add("SUSPICIOUS_TLD")
        }

        // H3: Excessive subdomain depth. Weak standalone signal — many
        // legitimate services use 3-4 level subdomains. Weight reduced
        // from v1.1.0 (was 15) since this should nudge, not drive, a
        // verdict.
        val subdomainDepth = host.split(".").size
        if (subdomainDepth >= 4) {
            score += 8
            flags.add("DEEP_SUBDOMAINS")
        }

        // --- Brand similarity (replaces v1.1.0's naive substring checks) ---
        // Normalize homoglyphs first so a Cyrillic/Greek/IPA clone of
        // "onlinesbi" is compared on equal footing with a plain-ASCII
        // typosquat.
        val normalizedHost = normalizeHomoglyphs(host)
        val hostHasHomoglyphs = normalizedHost != host
        val hostNoTld = normalizedHost.substringBeforeLast(".")

        val brandMatch = closestBrandMatch(hostNoTld)
        if (brandMatch != null) {
            val (brand, dist) = brandMatch
            // Closer match (smaller distance) = higher score. dist=1 is
            // the most dangerous/likely case (single char swap/typo).
            val brandScore = (45 - (dist * 10)).coerceAtLeast(10)
            score += brandScore
            flags.add(
                if (hostHasHomoglyphs) "HOMOGLYPH_BRAND_IMPERSONATION"
                else "BRAND_IMPERSONATION"
            )
            Log.d(TAG, "Brand match: '$hostNoTld' ~ '$brand' (dist=$dist, +$brandScore)")
        }

        val hasBrandRelevance = brandMatch != null

        // H5: Brand term appearing in the path is only meaningful if
        // the host itself doesn't already explain it (e.g. a CDN path
        // like /assets/sbi-logo.png on an unrelated legitimate site is
        // noise). Keep this modest and host-independent since it can
        // still indicate a clone hosted on a generic free domain
        // (e.g. freehost.com/sbi-login/kyc).
        if (officialBrandCores.any { path.contains(it) }) {
            score += 12
            flags.add("BRAND_IN_PATH")
        }

        // H7: URL shortener (hides actual destination)
        if (shortenerDomains.any { host == it || host.endsWith(".$it") }) {
            score += 25
            flags.add("URL_SHORTENER")
        }

        // H8: Non-standard port
        val port = uri.port
        if (port != -1 && port != 80 && port != 443) {
            score += 20
            flags.add("NON_STANDARD_PORT")
        }

        // H9: HTTP without TLS
        if (uri.scheme == "http") {
            score += 15
            flags.add("NO_TLS")
        }

        // H10: Suspicious path keywords (login, verify, kyc, update,
        // secure, otp, ...). v1.1.0 scored these standalone, which
        // false-positived on huge swaths of harmless content (news
        // articles, blog posts, docs pages mentioning "update" or
        // "secure" once). Now this ONLY contributes when there is
        // already brand relevance — either a brand-distance host match
        // or a brand term in the path — so it acts as a multiplier on
        // an existing signal, not an independent trigger.
        val suspiciousPathTerms = listOf(
            "login", "verify", "kyc", "update", "secure",
            "otp", "confirm", "validate", "unlock", "reactivate",
            "suspend", "block", "freeze", "password", "credential"
        )
        val pathMatches = suspiciousPathTerms.filter { path.contains(it) }
        if (pathMatches.isNotEmpty() && hasBrandRelevance) {
            score += 10 + (pathMatches.size * 5).coerceAtMost(15)
            flags.add("SUSPICIOUS_PATH")
        }

        // H11: Excessive URL length (phishing URLs tend to be long)
        if (fullUrl.length > 150) {
            score += 10
            flags.add("EXCESSIVE_LENGTH")
        }

        // H12: Contains encoded characters that suggest obfuscation
        if (fullUrl.contains("%2f", ignoreCase = true) ||
            fullUrl.contains("%3a", ignoreCase = true) ||
            fullUrl.contains("@")) {
            score += 15
            flags.add("URL_OBFUSCATION")
        }

        score = score.coerceAtMost(100)

        // --- Gated escalation ---
        // Generic/weak signals (TLD, length, port, subdomain depth,
        // obfuscation, path keywords without brand relevance) must NOT
        // be able to stack into a soft/hard verdict on their own. This
        // was the main source of "flags everything else" in v1.1.0,
        // where e.g. NON_STANDARD_PORT + EXCESSIVE_LENGTH + NO_TLS +
        // SUSPICIOUS_TLD alone (65 points, zero brand relevance) would
        // hit "hard". Now at least one structurally meaningful signal
        // is required to escalate at all.
        val hasStrongSignal = flags.any { it in strongSignalFlags }

        val verdict = when {
            !hasStrongSignal -> "none"
            score >= THRESHOLD_HARD -> "hard"
            score >= THRESHOLD_SOFT -> "soft"
            else -> "none"
        }

        return ScanResult(
            url = url,
            score = score,
            verdict = verdict,
            flags = flags,
            isSafe = verdict == "none"
        )
    }

    /**
     * Finds the closest official brand core to the given host label by
     * Levenshtein edit distance, restricted to BRAND_DIST_MAX. Returns
     * null if nothing is within range (i.e. host is not a plausible
     * clone of any known brand).
     *
     * dist == 0 is intentionally excluded — an exact match means the
     * domain literally equals a brand string with a different TLD/path
     * structure than expected; that's still worth flagging, so dist=0
     * is treated as dist=1 strength rather than ignored.
     */
    private fun closestBrandMatch(hostLabel: String): Pair<String, Int>? {
        var best: Pair<String, Int>? = null
        val labelTokens = hostLabel.split("-", "_", ".")
        
        for (brand in officialBrandCores) {
            if (brand.length < 5) {
                // Short brand cores (e.g. au, bob, upi, pnb) require EXACT token match
                if (labelTokens.contains(brand)) {
                    return brand to 1 // Treat exact token match as high confidence (dist=1)
                }
                continue
            }
            
            // Compare against the host label directly, and also against
            // the leading segment up to the first hyphen/dot-removed
            // boundary, to catch patterns like "sbi-yono-update" where
            // the brand is a prefix/component rather than the whole label.
            val dist = levenshtein(hostLabel, brand)
            val effectiveDist = if (dist == 0) 1 else dist
            
            val maxAllowedDist = when {
                brand.length <= 5 -> 1
                brand.length <= 7 -> 2
                else -> BRAND_DIST_MAX
            }
            
            if (dist <= maxAllowedDist) {
                if (best == null || effectiveDist < best!!.second) {
                    best = brand to effectiveDist
                }
            }
        }
        // Also check component-wise for compound labels like
        // "statebank-sbi-login" or "sbi-kyc-update" — split on common
        // separators and test each token.
        if (best == null) {
            val tokens = hostLabel.split("-", "_", ".").filter { it.length >= 3 }
            for (token in tokens) {
                for (brand in officialBrandCores) {
                    if (brand.length < 5) continue // Short cores are already handled by exact match above
                    
                    val dist = levenshtein(token, brand)
                    val maxAllowedDist = when {
                        brand.length <= 5 -> 1
                        brand.length <= 7 -> 2
                        else -> BRAND_DIST_MAX
                    }
                    
                    if (dist in 1..maxAllowedDist) {
                        if (best == null || dist < best!!.second) {
                            best = brand to dist
                        }
                    }
                }
            }
        }
        return best
    }

    /**
     * Standard iterative Levenshtein edit distance (insertions,
     * deletions, substitutions). O(n*m) time, O(min(n,m)) space.
     * Cheap enough to run per-token on-device at notification/URL
     * scan time — host labels are short strings.
     */
    private fun levenshtein(a: String, b: String): Int {
        if (a == b) return 0
        if (a.isEmpty()) return b.length
        if (b.isEmpty()) return a.length

        var prevRow = IntArray(b.length + 1) { it }
        var currRow = IntArray(b.length + 1)

        for (i in 1..a.length) {
            currRow[0] = i
            for (j in 1..b.length) {
                val cost = if (a[i - 1] == b[j - 1]) 0 else 1
                currRow[j] = minOf(
                    currRow[j - 1] + 1,      // insertion
                    prevRow[j] + 1,          // deletion
                    prevRow[j - 1] + cost    // substitution
                )
            }
            val tmp = prevRow
            prevRow = currRow
            currRow = tmp
        }
        return prevRow[b.length]
    }

    private fun isIpAddress(host: String): Boolean {
        // IPv4 pattern
        val ipv4 = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        if (ipv4.matches(host)) return true
        // IPv6 bracketed
        if (host.startsWith("[") && host.endsWith("]")) return true
        return false
    }

    /**
     * Maps known confusable (homoglyph) characters back to their
     * ASCII look-alike so the result can be compared against real
     * brand strings on equal footing. This is what lets the scanner
     * catch e.g. "оnlinesbi.com" (Cyrillic о) as a clone of
     * "onlinesbi" instead of just flagging "contains a weird char"
     * with no actual brand context.
     */
    private fun normalizeHomoglyphs(text: String): String {
        return text.map { char -> homoglyphMap[char] ?: char }.joinToString("")
    }

    /**
     * Result of a URL heuristic scan.
     */
    data class ScanResult(
        val url: String,
        val score: Int,
        val verdict: String,   // "none", "soft", "hard"
        val flags: List<String>,
        val isSafe: Boolean
    ) {
        fun toChannelMap(): HashMap<String, Any> {
            return hashMapOf(
                "url" to url,
                "score" to score,
                "verdict" to verdict,
                "flags" to flags,
                "isSafe" to isSafe
            )
        }
    }
}
