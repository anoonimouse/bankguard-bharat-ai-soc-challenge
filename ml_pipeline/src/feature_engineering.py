"""
Feature Engineering Module for Phishing URL Detection.

Extracts a rich feature vector from any URL for the XGBoost classifier.
This module is used both during training (ml_pipeline) and at inference
time (backend/ml/). Write it once, use it everywhere -- no drift.

Public API:
    extract_features(url: str) -> dict[str, float]
    FEATURE_NAMES: list[str]

Total features: 45 (41 original + 4 RBI .bank.in awareness features)
"""

import os
import re
import math
import string
from urllib.parse import urlparse, parse_qs
from collections import Counter

# Import whitelist tiers for cross-referencing in claims_bank_wrong_domain
# Handles both ml_pipeline/src/ and backend/ml/ import contexts
try:
    from whitelist import TIER_1_BANK_IN_DOMAINS, TIER_2_LEGACY_DOMAINS, TIER_3_GENERAL_TRUSTED
except ImportError:
    try:
        from .whitelist import TIER_1_BANK_IN_DOMAINS, TIER_2_LEGACY_DOMAINS, TIER_3_GENERAL_TRUSTED
    except ImportError:
        # fallback if whitelist not available -- feature will always return 0
        TIER_1_BANK_IN_DOMAINS = set()
        TIER_2_LEGACY_DOMAINS = set()
        TIER_3_GENERAL_TRUSTED = set()

# Levenshtein distance - use python-Levenshtein if available, else fallback
try:
    from Levenshtein import distance as _lev_distance
except ImportError:
    def _lev_distance(s1: str, s2: str) -> int:
        """Pure-Python Levenshtein distance fallback."""
        if len(s1) < len(s2):
            return _lev_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]


# =========================================================================
# Constants
# =========================================================================

HIGH_RISK_TLDS = {
    "xyz", "pw", "top", "club", "icu", "buzz", "online", "site", "fun",
    "click", "link", "info", "tk", "ml", "ga", "cf", "gq", "cam",
    "win", "stream", "racing", "download", "review", "cricket",
    "accountant", "loan", "date", "faith", "trade", "bid", "party",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
    "bl.ink", "clck.ru", "v.gd", "x.co",
}

SBI_KEYWORDS = {"sbi", "yono", "freedom", "lotusintouch", "onlinesbi", "sbifreedom"}
BANKING_KEYWORDS = {"bank", "account", "secure", "login", "verify", "netbanking", "mobile-banking"}
KYC_KEYWORDS = {"kyc", "update", "expire", "mandatory", "renew", "rekyc"}
URGENCY_KEYWORDS = {"urgent", "immediate", "suspend", "block", "expire", "warning", "alert", "critical"}
REWARD_KEYWORDS = {"reward", "cashback", "prize", "claim", "bonus", "offer", "free", "win"}
APK_KEYWORDS = {".apk", "download", "install"}
VOWELS = set("aeiou")
CONSONANTS = set(string.ascii_lowercase) - VOWELS


# =========================================================================
# Helper Functions
# =========================================================================

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_ip_address(host: str) -> bool:
    """Check if host is an IP address (v4 or v6)."""
    # IPv4 pattern
    ipv4 = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)
    if ipv4:
        return True
    # IPv6 pattern (simplified - bracketed or bare hex)
    if ":" in host and all(c in "0123456789abcdef:[]" for c in host.lower()):
        return True
    return False


def _extract_tld(domain: str) -> str:
    """Extract TLD from domain. Handles compound TLDs like co.in, co.uk, bank.in."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov", "bank", "fin"):
        return f"{parts[-2]}.{parts[-1]}"
    if len(parts) >= 2:
        return parts[-1]
    return domain


def _is_bank_in_tld(hostname: str) -> bool:
    """
    Check if hostname has .bank.in as its actual TLD.

    Uses proper suffix matching -- the hostname must end with .bank.in
    AND the part before .bank.in must be a valid label (not empty).

    Examples:
        sbi.bank.in           -> True
        onlinesbi.sbi.bank.in -> True
        sbi.bank.in.evil.xyz  -> False (bank.in is not the TLD here)
        bank.in               -> True  (bare zone, unlikely but valid)
    """
    if not hostname:
        return False
    # hostname must end with .bank.in or be exactly X.bank.in
    if hostname == "bank.in":
        return True
    return hostname.endswith(".bank.in")


def _is_fin_in_tld(hostname: str) -> bool:
    """
    Check if hostname has .fin.in as its actual TLD (NBFC domain).

    Same logic as _is_bank_in_tld but for the RBI-mandated NBFC namespace.
    """
    if not hostname:
        return False
    if hostname == "fin.in":
        return True
    return hostname.endswith(".fin.in")


def _tokenize_domain(domain: str) -> list:
    """Split domain into meaningful tokens by dots, hyphens, and digit boundaries."""
    # Remove TLD
    parts = domain.split(".")
    if len(parts) > 1:
        parts = parts[:-1]  # Drop TLD
    name = ".".join(parts)
    # Split on dots, hyphens, underscores, and digit/letter boundaries
    tokens = re.split(r"[-._]", name)
    # Further split on digit/letter boundaries
    expanded = []
    for t in tokens:
        expanded.extend(re.findall(r"[a-zA-Z]+|\d+", t))
    return [t for t in expanded if t]


# =========================================================================
# Main Feature Extraction
# =========================================================================

def extract_features(url: str) -> dict:
    """
    Extract a comprehensive feature vector from a URL.

    Returns a dictionary of feature_name -> float value.
    All features are numeric (int or float).
    """
    if not url:
        url = ""

    # Normalize
    url_lower = url.lower()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        url_lower = "http://" + url_lower
        url = "http://" + url

    try:
        parsed = urlparse(url_lower)
    except Exception:
        parsed = urlparse("")

    domain = parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    hostname = domain.split(":")[0]  # Strip port
    tld = _extract_tld(hostname) if hostname else ""
    domain_tokens = _tokenize_domain(hostname)

    features = {}

    # ----- Lexical Features -----

    # Total character length of full URL
    features["url_length"] = len(url)

    # Length of domain only
    features["domain_length"] = len(domain)

    # Length of path component
    features["path_length"] = len(path)

    # Length of query string
    features["query_length"] = len(query)

    # Length of fragment
    features["fragment_length"] = len(fragment)

    # Number of dots in full URL
    features["num_dots"] = url.count(".")

    # Number of hyphens in full URL
    features["num_hyphens"] = url.count("-")

    # Number of underscores
    features["num_underscores"] = url.count("_")

    # Number of forward slashes
    features["num_slashes"] = url.count("/")

    # Total digit count in URL
    features["num_digits"] = sum(1 for c in url if c.isdigit())

    # Count of special characters: @, !, %, +, =, $
    special = set("@!%+=$")
    features["num_special_chars"] = sum(1 for c in url if c in special)

    # Digits divided by total URL length
    features["digit_ratio"] = features["num_digits"] / max(len(url), 1)

    # Uppercase chars divided by total length
    features["uppercase_ratio"] = sum(1 for c in url if c.isupper()) / max(len(url), 1)

    # ----- Domain Features -----

    # Number of subdomains (dots in hostname minus 1)
    dot_count = hostname.count(".")
    features["subdomain_count"] = max(0, dot_count - 1)

    # Is the host an IP address
    features["has_ip_address"] = 1 if _is_ip_address(hostname) else 0

    # TLD encoded as high/low risk binary (categorical encoding unnecessary for tree model)
    features["tld_is_high_risk"] = 1 if tld in HIGH_RISK_TLDS else 0

    # Does domain contain digits
    features["domain_has_digits"] = 1 if any(c.isdigit() for c in hostname) else 0

    # Does domain contain hyphen
    features["domain_has_hyphen"] = 1 if "-" in hostname else 0

    # Known URL shortener domain
    features["is_url_shortener"] = 1 if hostname in URL_SHORTENERS else 0

    # Number of meaningful tokens in domain name
    features["domain_token_count"] = len(domain_tokens)

    # ----- Entropy Features -----

    # Shannon entropy of full URL string - high entropy = random/obfuscated
    features["url_entropy"] = _shannon_entropy(url)

    # Shannon entropy of domain string
    features["domain_entropy"] = _shannon_entropy(hostname)

    # Shannon entropy of path string
    features["path_entropy"] = _shannon_entropy(path)

    # ----- Brand Similarity Features -----
    # Levenshtein distance from domain to known brand names.
    # Low distance + phishing TLD = strong signal

    features["lev_dist_sbi"] = _lev_distance(hostname, "sbi")
    features["lev_dist_onlinesbi"] = _lev_distance(hostname, "onlinesbi")
    features["lev_dist_yono"] = _lev_distance(hostname, "yono")
    features["lev_dist_sbifreedom"] = _lev_distance(hostname, "sbifreedom")

    # URL contains SBI-related keywords
    features["contains_sbi_keyword"] = 1 if any(kw in url_lower for kw in SBI_KEYWORDS) else 0

    # URL contains generic banking keywords
    features["contains_banking_keyword"] = 1 if any(kw in url_lower for kw in BANKING_KEYWORDS) else 0

    # ----- Suspicious Pattern Features -----

    # KYC keywords
    features["contains_kyc_keyword"] = 1 if any(kw in url_lower for kw in KYC_KEYWORDS) else 0

    # Urgency keywords
    features["contains_urgency_keyword"] = 1 if any(kw in url_lower for kw in URGENCY_KEYWORDS) else 0

    # Reward keywords
    features["contains_reward_keyword"] = 1 if any(kw in url_lower for kw in REWARD_KEYWORDS) else 0

    # APK keywords
    features["contains_apk_keyword"] = 1 if any(kw in url_lower for kw in APK_KEYWORDS) else 0

    # @ symbol in URL (obfuscation technique)
    features["has_at_symbol"] = 1 if "@" in url else 0

    # Double slash redirect (// after scheme)
    after_scheme = url_lower.split("://", 1)[1] if "://" in url_lower else url_lower
    features["has_double_slash_redirect"] = 1 if "//" in after_scheme else 0

    # Number of path segments
    path_segments = [s for s in path.split("/") if s]
    features["path_depth"] = len(path_segments)

    # Path contains login/auth terms
    features["has_login_path"] = 1 if any(
        kw in path.lower() for kw in ("login", "signin", "auth", "sign-in", "log-in")
    ) else 0

    # Brand keyword + high risk TLD together - very strong phishing signal
    has_brand = features["contains_sbi_keyword"] or features["contains_banking_keyword"]
    features["has_suspicious_tld_combo"] = 1 if (has_brand and features["tld_is_high_risk"]) else 0

    # ----- Statistical Features -----

    # Ratio of consonants to vowels in domain
    domain_alpha = [c for c in hostname.lower() if c.isalpha()]
    vowel_count = sum(1 for c in domain_alpha if c in VOWELS)
    consonant_count = sum(1 for c in domain_alpha if c in CONSONANTS)
    features["consonant_vowel_ratio"] = consonant_count / max(vowel_count, 1)

    # Length of longest token in domain
    features["longest_word_length"] = max((len(t) for t in domain_tokens), default=0)

    # Mean length of domain tokens
    features["average_token_length"] = (
        sum(len(t) for t in domain_tokens) / max(len(domain_tokens), 1)
    )

    # ----- RBI .bank.in Domain Features (v1.1.0) -----
    # Post October 2025, all Indian banks must operate on .bank.in domains.
    # These features encode this regulatory mandate as detection signals.

    # is_bank_in_domain: Trust signal -- verified RBI-regulated domain.
    # Expected direction: strong NEGATIVE contribution to phishing probability.
    # Example trigger: https://sbi.bank.in/personal-banking -> 1
    features["is_bank_in_domain"] = 1 if _is_bank_in_tld(hostname) else 0

    # is_fin_in_domain: Trust signal -- NBFC regulated domain.
    # Expected direction: NEGATIVE contribution to phishing probability.
    # Example trigger: https://bajaj.fin.in/ -> 1
    features["is_fin_in_domain"] = 1 if _is_fin_in_tld(hostname) else 0

    # claims_bank_wrong_domain: Phishing signal -- URL claims to be an Indian
    # bank but is NOT on .bank.in, NOT on a legacy trusted domain, and NOT
    # on a known general trusted site. After Oct 2025, any banking URL that
    # isn't on .bank.in or a legacy redirect domain is inherently suspicious.
    # Expected direction: strong POSITIVE contribution to phishing probability.
    # Example trigger: http://sbi-kyc-update.xyz/verify -> 1
    has_bank_keywords = features["contains_sbi_keyword"] or features["contains_banking_keyword"]
    on_bank_in = features["is_bank_in_domain"] == 1
    on_trusted = hostname in TIER_1_BANK_IN_DOMAINS or hostname in TIER_2_LEGACY_DOMAINS or hostname in TIER_3_GENERAL_TRUSTED
    features["claims_bank_wrong_domain"] = 1 if (has_bank_keywords and not on_bank_in and not on_trusted) else 0

    # is_bank_in_lookalike: Strong phishing signal -- detects visual mimicry
    # of .bank.in without the real TLD. Catches subdomain abuse, hyphen
    # insertion, and namespace confusion attempts.
    # Expected direction: very strong POSITIVE contribution to phishing probability.
    # Example trigger: http://sbi.bank-in.com/login -> 1
    lookalike = False
    if not on_bank_in:
        # check for various mimicry patterns
        if "bank-in" in url_lower:                          # hyphen insertion
            lookalike = True
        elif "bankin" in hostname and ".bank.in" not in hostname:  # no dot
            lookalike = True
        elif ".bank.in." in url_lower:                      # subdomain abuse
            lookalike = True
        elif "bank_in" in hostname:                          # underscore
            lookalike = True
        # check for .bank.com, .bank.net etc -- TLD impersonation
        elif hostname.endswith(".bank.com") or hostname.endswith(".bank.net") or hostname.endswith(".bank.org"):
            lookalike = True
    features["is_bank_in_lookalike"] = 1 if lookalike else 0

    return features


# Canonical ordered list of feature names (must match training order)
# v1.1.0: appended 4 new .bank.in features at end (positions 41-44)
FEATURE_NAMES = [
    "url_length", "domain_length", "path_length", "query_length", "fragment_length",
    "num_dots", "num_hyphens", "num_underscores", "num_slashes", "num_digits",
    "num_special_chars", "digit_ratio", "uppercase_ratio",
    "subdomain_count", "has_ip_address", "tld_is_high_risk",
    "domain_has_digits", "domain_has_hyphen", "is_url_shortener", "domain_token_count",
    "url_entropy", "domain_entropy", "path_entropy",
    "lev_dist_sbi", "lev_dist_onlinesbi", "lev_dist_yono", "lev_dist_sbifreedom",
    "contains_sbi_keyword", "contains_banking_keyword",
    "contains_kyc_keyword", "contains_urgency_keyword", "contains_reward_keyword",
    "contains_apk_keyword",
    "has_at_symbol", "has_double_slash_redirect", "path_depth", "has_login_path",
    "has_suspicious_tld_combo",
    "consonant_vowel_ratio", "longest_word_length", "average_token_length",
    # v1.1.0 -- RBI .bank.in domain awareness features
    "is_bank_in_domain", "is_fin_in_domain",
    "claims_bank_wrong_domain", "is_bank_in_lookalike",
]

# Validate at import time
assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)), "Duplicate feature names!"
