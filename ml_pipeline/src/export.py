"""
Model Export Script -- Prepare artifacts for backend deployment.

Exports trained model + metadata to the models/ directory, then runs a
sanity check on known phishing and legitimate URLs to validate before deploy.
Uses the three-tier trusted domain whitelist to override false positives on
known-good domains -- a whitelist override is a PASS, not a FAIL.

Usage:
    python src/export.py

Gate: prints "EXPORT VALIDATION PASSED" only if all assertions pass.
"""

import os
import sys
import json
import shutil
import logging
import platform
from datetime import datetime

import joblib
import xgboost
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from feature_engineering import extract_features, FEATURE_NAMES
from whitelist import get_domain_trust_tier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, "models")
SRC_DIR = os.path.join(BASE_DIR, "src")


# =========================================================================
# Known test URLs for sanity check -- v1.1.0 expanded with .bank.in
# =========================================================================

KNOWN_PHISHING = [
    # Original India-specific phishing set
    "http://yonosbi-update.xyz/login",
    "http://sbi-kyc-update.pw/verify",
    "http://onlinesbi-secure.app/auth",
    "http://yono-verification.xyz/account",
    "http://sbi-netbanking-login.com/portal",
    "http://upi-kyc-update.pw/verify",
    "http://sbi-reward-cashback.xyz/claim",
    "http://account-verify-sbi.xyz/login",
    "http://yonosbi-secure123.pw/kyc",
    "http://sbi-alert-007.xyz/urgent",
    # Subdomain abuse and edge cases
    "http://sbi.co.in.phishing-site.xyz/login",
    "http://yono-sbi-secure.app/kyc/update/verify",
    "http://192.168.1.1/sbi/login",
    "http://onlinesbi-alert.com/account/suspended",
    "http://secure-sbi-banking.xyz/verify/otp",
    # v1.1.0 -- .bank.in lookalike phishing
    "http://sbi.bank-in.com/login",
    "http://hdfc.bank-in.xyz/netbanking",
    "http://sbi.bank.in.phishing-site.xyz/login",
    "http://icici.bank.in.kyc-update.pw/verify",
    "http://sbibankin-login.com/verify",
    "http://sbi.bank.com/login",
    "http://hdfc.bank.net/netbanking",
    "http://sbi-bank-in-migration.xyz/verify",
]

KNOWN_LEGITIMATE = [
    # Bare domains
    "https://www.google.com",
    "https://www.sbi.co.in",
    "https://yono.sbi",
    "https://www.hdfcbank.com",
    "https://www.amazon.in",
    "https://www.github.com",
    "https://www.wikipedia.org",
    "https://www.rbi.org.in",
    "https://www.flipkart.com",
    "https://www.python.org",
    # Path variants
    "https://www.google.com/search?q=sbi+banking",
    "https://www.github.com/user/repository",
    "https://www.wikipedia.org/wiki/State_Bank_of_India",
    "https://www.hdfcbank.com/personal/pay/cards",
    "https://www.flipkart.com/mobiles/pr",
    "https://www.python.org/downloads/release",
    "https://stackoverflow.com/questions/12345",
    "https://www.rbi.org.in/scripts/home.aspx",
    "https://www.npci.org.in/what-we-do/upi",
    # v1.1.0 -- .bank.in verified domains (Tier 1)
    "https://sbi.bank.in",
    "https://sbi.bank.in/personal-banking/accounts/savings-account",
    "https://hdfc.bank.in",
    "https://hdfc.bank.in/personal/pay/cards/credit-cards",
    "https://icici.bank.in",
    "https://axis.bank.in",
    "https://kotak.bank.in",
    "https://pnb.bank.in",
    "https://onlinesbi.sbi.bank.in/personal/login",
]

# Tier labels for logging
_TIER_LABELS = {1: "TIER1", 2: "TIER2", 3: "TIER3"}


def create_metadata(model, metrics_path: str) -> dict:
    """Build model metadata for deployment tracking."""
    metrics = {}
    if os.path.exists(metrics_path):
        with open(metrics_path, "r", encoding="utf-8") as f:
            metrics = json.load(f)

    return {
        "model_version": "1.1.0",
        "training_date": datetime.now().isoformat(),
        "xgboost_version": xgboost.__version__,
        "python_version": platform.python_version(),
        "feature_count": len(FEATURE_NAMES),
        "performance": metrics,
        "notes": "v1.1.0 -- RBI .bank.in domain awareness, three-tier whitelist, 4 new features",
        "upgrade_notes": (
            "Added is_bank_in_domain, is_fin_in_domain, claims_bank_wrong_domain, "
            "is_bank_in_lookalike features. Restructured whitelist into 3 tiers. "
            "Feature count changed from 41 to 45 -- model is NOT backward compatible with v2.0.0."
        ),
        "rbi_mandate_compliance": {
            "mandate": "All Indian banks must operate on .bank.in domains",
            "deadline": "2025-10-31",
            "registrar": "IDRBT (Institute for Development and Research in Banking Technology)",
            "namespace_operator": "NIXI/MeitY",
        },
        "regulatory_reference": "RBI Circular April 2025 -- Mandatory .bank.in migration for all scheduled commercial banks",
    }


def run_sanity_check(model, threshold: float) -> bool:
    """
    Validate model on known URLs.

    For legitimate URLs on trusted domains, a whitelist override
    is logged with its tier (TIER1/TIER2/TIER3). The check
    only FAILs if:
      - A phishing URL scores below threshold (missed phishing)
      - A non-whitelisted legitimate URL scores above threshold
    """
    logger.info("Running sanity check on known URLs...")
    all_passed = True
    override_count = 0
    tier_overrides = {1: 0, 2: 0, 3: 0}

    # Check phishing URLs -- must all score above threshold
    for url in KNOWN_PHISHING:
        features = extract_features(url)
        vec = np.array([[features[name] for name in FEATURE_NAMES]])
        prob = model.predict_proba(vec)[0, 1]
        passed = prob >= threshold
        status = "[PASS]" if passed else "[FAIL]"
        logger.info(f"  {status} PHISHING  prob={prob:.3f}  {url}")
        if not passed:
            all_passed = False

    # Check legitimate URLs -- must score below threshold, or be whitelisted
    for url in KNOWN_LEGITIMATE:
        features = extract_features(url)
        vec = np.array([[features[name] for name in FEATURE_NAMES]])
        prob = model.predict_proba(vec)[0, 1]
        model_says_legit = prob < threshold
        tier = get_domain_trust_tier(url)

        if model_says_legit:
            # model got it right on its own
            status = "[PASS]"
        elif tier > 0:
            # model was wrong but whitelist saves it -- not a failure
            tier_label = _TIER_LABELS.get(tier, f"TIER{tier}")
            status = f"[{tier_label}_WHITELIST]"
            override_count += 1
            tier_overrides[tier] = tier_overrides.get(tier, 0) + 1
        else:
            # model was wrong and no whitelist safety net
            status = "[FAIL]"
            all_passed = False

        logger.info(f"  {status} LEGIT     prob={prob:.3f}  {url}")

    if override_count > 0:
        parts = [f"Tier {t}: {c}" for t, c in sorted(tier_overrides.items()) if c > 0]
        logger.info(f"  Note: {override_count} whitelist override(s) -- {', '.join(parts)}")

    return all_passed


def main():
    model_path = os.path.join(MODELS_DIR, "xgb_phishing_model.pkl")
    fn_path = os.path.join(MODELS_DIR, "feature_names.json")
    threshold_path = os.path.join(MODELS_DIR, "optimal_threshold.json")
    metrics_path = os.path.join(MODELS_DIR, "evaluation_metrics.json")

    # Verify all required files exist
    for path, name in [(model_path, "model"), (fn_path, "feature names"),
                        (threshold_path, "threshold")]:
        if not os.path.exists(path):
            logger.error(f"Missing {name} at {path} -- run train.py and evaluate.py first")
            sys.exit(1)

    # Load model and threshold
    model = joblib.load(model_path)
    with open(threshold_path, "r", encoding="utf-8") as f:
        threshold = json.load(f)["threshold"]

    # Create metadata
    metadata = create_metadata(model, metrics_path)
    metadata_path = os.path.join(MODELS_DIR, "model_metadata.json")
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info(f"Metadata saved to {metadata_path}")

    # Copy feature_engineering.py to models/ for backend deployment
    fe_src = os.path.join(SRC_DIR, "feature_engineering.py")
    fe_dst = os.path.join(MODELS_DIR, "feature_engineering.py")
    shutil.copy2(fe_src, fe_dst)
    logger.info(f"feature_engineering.py copied to {fe_dst}")

    # Copy whitelist.py to models/ for backend deployment
    wl_src = os.path.join(SRC_DIR, "whitelist.py")
    wl_dst = os.path.join(MODELS_DIR, "whitelist.py")
    shutil.copy2(wl_src, wl_dst)
    logger.info(f"whitelist.py copied to {wl_dst}")

    # Run sanity check -- the mandatory gate
    passed = run_sanity_check(model, threshold)

    print()
    if passed:
        print("=" * 50)
        print("  EXPORT VALIDATION PASSED")
        print("=" * 50)
        print()
        print("All artifacts ready in models/:")
        print(f"  - xgb_phishing_model.pkl")
        print(f"  - feature_names.json")
        print(f"  - optimal_threshold.json")
        print(f"  - model_metadata.json")
        print(f"  - feature_engineering.py")
        print(f"  - whitelist.py")
        print(f"  - evaluation_report.txt")
        print()
        print(f"Model version: {metadata['model_version']}")
        print(f"Feature count: {metadata['feature_count']}")
    else:
        print("=" * 50)
        print("  EXPORT VALIDATION FAILED")
        print("=" * 50)
        print()
        print("Some known URLs were misclassified.")
        print("Review the model, threshold, and feature engineering.")
        print("Do NOT deploy this model to production.")
        sys.exit(1)


if __name__ == "__main__":
    main()
