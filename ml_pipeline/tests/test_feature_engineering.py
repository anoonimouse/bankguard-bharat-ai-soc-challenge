"""Unit tests for feature_engineering module."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from feature_engineering import extract_features, FEATURE_NAMES


def test_feature_count():
    """Verify all features are extracted."""
    features = extract_features("https://www.google.com")
    assert len(features) == len(FEATURE_NAMES), f"Expected {len(FEATURE_NAMES)}, got {len(features)}"
    for name in FEATURE_NAMES:
        assert name in features, f"Missing feature: {name}"


def test_empty_url():
    """Handle empty/None URLs gracefully."""
    features = extract_features("")
    assert isinstance(features, dict)
    assert features["url_length"] == len("http://")  # Prepended


def test_phishing_url_signals():
    """Phishing URLs should trigger expected feature signals."""
    features = extract_features("http://yonosbi-update.xyz/login")
    assert features["contains_sbi_keyword"] == 1
    assert features["tld_is_high_risk"] == 1
    assert features["has_suspicious_tld_combo"] == 1
    assert features["has_login_path"] == 1
    assert features["domain_has_hyphen"] == 1
    assert features["contains_kyc_keyword"] == 0  # No kyc in this URL


def test_legitimate_url_signals():
    """Legitimate URLs should not trigger phishing signals."""
    features = extract_features("https://www.google.com")
    assert features["contains_sbi_keyword"] == 0
    assert features["tld_is_high_risk"] == 0
    assert features["has_suspicious_tld_combo"] == 0
    assert features["has_ip_address"] == 0
    assert features["is_url_shortener"] == 0


def test_ip_address_detection():
    """Detect IP address hosts."""
    features = extract_features("http://192.168.1.1/login")
    assert features["has_ip_address"] == 1


def test_url_shortener_detection():
    """Detect known URL shorteners."""
    features = extract_features("https://bit.ly/abc123")
    assert features["is_url_shortener"] == 1


def test_entropy_non_negative():
    """Entropy values should always be non-negative."""
    for url in ["https://google.com", "http://x.xyz/a", "https://a" * 50]:
        features = extract_features(url)
        assert features["url_entropy"] >= 0
        assert features["domain_entropy"] >= 0
        assert features["path_entropy"] >= 0


def test_levenshtein_distances():
    """Verify Levenshtein distances are reasonable."""
    features = extract_features("https://sbi.co.in")
    assert features["lev_dist_sbi"] < features["lev_dist_sbifreedom"]

    # Exact match should have low distance
    features2 = extract_features("https://yono.sbi")
    assert features2["lev_dist_yono"] < 10


def test_brand_keyword_detection():
    """SBI and banking keyword detection."""
    features = extract_features("http://sbi-kyc-update.xyz/verify")
    assert features["contains_sbi_keyword"] == 1
    assert features["contains_kyc_keyword"] == 1
    assert features["contains_banking_keyword"] == 0  # No 'login', 'account', etc.


def test_at_symbol():
    """@ symbol detection for URL obfuscation."""
    features = extract_features("http://user@evil.com/path")
    assert features["has_at_symbol"] == 1


def test_feature_names_unique():
    """Feature names list has no duplicates."""
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  [PASS] {test.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests")
    sys.exit(1 if failed > 0 else 0)
