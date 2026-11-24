f"""
Data Collection Script for BankGuard ML Phishing Pipeline.

Downloads phishing and legitimate URL datasets from multiple public sources,
cleans and balances the data, then outputs a labeled CSV for training.

Sources:
  Phishing:  PhishTank (bulk JSON), OpenPhish (feed.txt),
             Phishing.Database (GitHub), India-specific curated list
  Legitimate: Tranco Top 1M, Indian banking/government curated list

Usage:
    python src/data_collection.py
"""

import os
import io
import csv
import gzip
import json
import math
import random
import hashlib
import logging
import requests
from urllib.parse import urlparse
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Paths relative to ml_pipeline root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
OUTPUT_CSV = os.path.join(PROCESSED_DIR, "labeled_urls.csv")

# Reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)


# =========================================================================
# India-specific curated phishing URL patterns (positive class supplement)
# =========================================================================
INDIA_PHISHING_URLS = [
    # SBI/YONO lookalike domains
    "http://yonosbi-update.xyz/login", "http://yono-sbi-kyc.com/verify",
    "http://sbi-kyc-update.in/rekyc", "http://onlinesbi-update.xyz/secure",
    "http://sbi-verification.pw/account", "http://yonosbi-secure.app/auth",
    "http://sbi-netbanking-login.com/portal", "http://yono-update.xyz/kyc",
    "http://sbi-alert-update.pw/verify", "http://sbi-portal-secure.xyz/login",
    "http://yono-kyc-mandatory.com/update", "http://sbi-login-secure.xyz/auth",
    "http://yono-security-update.pw/rekyc", "http://sbi-mobile-update.xyz/install",
    "http://sbi-app-update.com/download", "http://yono-verification.xyz/account",
    "http://sbi-help-desk.pw/support", "http://yono-support-sbi.com/ticket",
    "http://sbi-wallet-update.xyz/kyc", "http://sbi-netbank-update.pw/login",
    "http://yonosbi-login.in/auth", "http://sbi-freedom-update.xyz/verify",
    "http://onlinesbi-kyc.pw/mandatory", "http://sbi-security-alert.xyz/urgent",
    "http://yono-sbi-secure.app/login", "http://sbi-kyc-verify.in/update",
    "http://yonosbi-portal.xyz/account", "http://sbi-update-kyc.pw/rekyc",
    "http://yono-login-sbi.com/auth", "http://sbi-verification-portal.xyz/verify",
    # UPI fraud patterns
    "http://upi-verification.xyz/update", "http://upi-kyc-update.pw/verify",
    "http://upi-pin-reset.com/secure", "http://upi-update-mandatory.xyz/kyc",
    # APK distribution
    "http://sbi-app-download.xyz/install.apk", "http://yono-update.pw/download-apk",
    "http://onlinesbi-app.xyz/update.apk", "http://sbi-freedom.pw/latest.apk",
    # OTP / SMS fraud
    "http://otp-verify-sbi.xyz/link", "http://sms-update-sbi.pw/verify",
    "http://otp-link-yono.com/auth", "http://sbi-otp-update.xyz/verify",
    # Account / reward fraud
    "http://account-verify-sbi.xyz/login", "http://re-kyc-sbi.pw/mandatory",
    "http://quick-kyc-sbi.com/update", "http://sbi-reward-cashback.xyz/claim",
    "http://yono-prize-winner.pw/claim", "http://sbi-cashback-offer.com/redeem",
    # Variations with numbers and hyphens
    "http://sbi-kyc-update1.xyz/verify", "http://yono-sbi-2024.pw/login",
    "http://onlinesbi-update99.com/auth", "http://sbi-alert-007.xyz/urgent",
    "http://yonosbi-secure123.pw/kyc", "http://sbi-portal-new.xyz/login",
    "http://yono-update-now.com/mandatory", "http://sbi-verify-today.pw/account",
    "http://sbi-kyc-expire.xyz/renew", "http://yono-suspend-alert.pw/verify",
    "http://sbi-block-warning.com/urgent", "http://yono-immediate-kyc.xyz/update",
    # More realistic Indian TLD patterns
    "http://sbikyc.co.in.myfakesite.xyz/login",
    "http://onlinesbi.sbi.verify-now.pw/kyc",
    "http://yono.sbi.secure-update.xyz/auth",
    "http://netbanking.sbi.kyc-renew.com/update",
    "http://sbi-freedom.co.in.update-app.xyz/download",
    # Subdomain abuse patterns
    "http://sbi.update-kyc-now.xyz/verify",
    "http://yono.secure-login-portal.pw/auth",
    "http://onlinesbi.kyc-mandatory.com/update",
    "http://netbanking.sbi-verification.xyz/login",
    "http://sbi.alert-security-urgent.pw/block",
    # With HTTPS to look more legitimate
    "https://yonosbi-update-secure.xyz/login",
    "https://sbi-kyc-portal.pw/verify",
    "https://onlinesbi-secure-login.com/auth",
    "https://yono-mandatory-kyc.xyz/update",
    "https://sbi-verification-center.pw/account",
    # International phishing targeting NRI
    "http://sbi-nri-update.xyz/kyc", "http://yono-global-login.pw/auth",
    "http://onlinesbi-nri-portal.com/verify", "http://sbi-abroad-update.xyz/secure",
    # Typosquatting
    "http://yonosb1.xyz/login", "http://sb1online.pw/kyc",
    "http://yon0sbi.com/auth", "http://sblonline.xyz/update",
    "http://yonosbl.pw/verify", "http://onlinesb1.com/portal",
    "http://sblyono.xyz/login", "http://yonosbii.pw/kyc",
    # ICICI/HDFC/Axis fraud patterns (cross-bank, not just SBI)
    "http://icici-kyc-update.xyz/verify", "http://hdfc-netbanking-login.pw/auth",
    "http://axis-bank-update.com/kyc", "http://kotak-verify-account.xyz/login",
    "http://bob-kyc-mandatory.pw/update", "http://pnb-account-update.com/verify",
    # Fake RBI / government
    "http://rbi-kyc-update.xyz/mandatory", "http://income-tax-refund.pw/claim",
    "http://aadhaar-link-bank.com/verify", "http://pan-kyc-update.xyz/link",
    # More APK variants
    "http://sbi-secure-banking.xyz/SBIYono.apk",
    "http://yono-latest-version.pw/update-v3.2.apk",
    "http://download-yono-sbi.com/YONO_SBI_Official.apk",
    # WhatsApp/social media spread patterns
    "http://sbi-6000-cashback.xyz/claim-now",
    "http://pm-yojana-sbi.pw/apply-free",
    "http://sbi-credit-card-offer.xyz/instant-approval",
    "http://yono-free-insurance.pw/register",
    # Long deceptive URLs
    "http://www.onlinesbi.sbi.co.in.kyc-update-verification-mandatory-portal.xyz/secure/verify/account",
    "http://yono.sbi.secure.banking.portal.update-now-or-account-blocked.pw/login",
    "http://sbi.freedom.plus.account.verification.mandatory.immediate.xyz/auth/kyc",
    "http://secure-sbi-banking.xyz/verify/otp",

    # Short-path SBI phishing patterns -- model currently undershoots these
    "http://account-verify-sbi.xyz/login",
    "http://sbi-account-verify.xyz/login",
    "http://verify-sbi-account.xyz/auth",
    "http://sbi-login-verify.xyz/",
    "http://account-sbi-update.xyz/login",
    "http://sbi-verify-now.xyz/login",
    "http://sbi-account-login.xyz/",
    "http://verify-account-sbi.pw/login",
    "http://sbi-secure-verify.xyz/account",
    "http://account-update-sbi.xyz/auth",
]

# Expand to ~250 with programmatic variations
def _expand_india_urls(base_urls: list) -> list:
    """Generate additional variations from base patterns."""
    expanded = list(base_urls)
    tlds = [".xyz", ".pw", ".app", ".top", ".club", ".icu", ".buzz", ".online", ".site", ".fun"]
    prefixes = ["sbi-", "yono-", "onlinesbi-", "sbi-kyc-", "yono-update-", "sbi-verify-"]
    suffixes = ["-update", "-kyc", "-login", "-verify", "-secure", "-portal", "-alert"]
    paths = ["/login", "/verify", "/kyc", "/update", "/auth", "/account", "/secure"]

    while len(expanded) < 250:
        prefix = random.choice(prefixes)
        suffix = random.choice(suffixes)
        tld = random.choice(tlds)
        path = random.choice(paths)
        num = random.randint(1, 999)
        url = f"http://{prefix}{num}{suffix}{tld}{path}"
        if url not in expanded:
            expanded.append(url)

    return expanded


# =========================================================================
# Indian legitimate banking / government URLs (negative class supplement)
# =========================================================================
INDIA_LEGITIMATE_URLS = [
    "https://www.onlinesbi.sbi", "https://sbi.co.in", "https://yono.sbi",
    "https://www.sbi.co.in", "https://retail.onlinesbi.sbi",
    "https://www.sbifreedom.in", "https://sbiyono.sbi",
    "https://www.rbi.org.in", "https://www.npci.org.in",
    "https://www.hdfcbank.com", "https://www.icicibank.com",
    "https://www.axisbank.com", "https://www.kotak.com",
    "https://www.bankofbaroda.in", "https://www.pnbindia.in",
    "https://www.idrbtca.org.in", "https://www.canarabank.com",
    "https://www.unionbankofindia.co.in", "https://www.indianbank.in",
    "https://www.centralbankofindia.co.in", "https://www.bankofindia.co.in",
    "https://www.idbibank.in", "https://www.yesbank.in",
    "https://www.indusind.com", "https://www.federalbank.co.in",
    "https://www.southindianbank.com", "https://www.karnatakabank.com",
    "https://www.dbs.com/india", "https://www.standardchartered.co.in",
    "https://www.citibank.co.in", "https://www.hsbc.co.in",
    "https://www.barclays.in", "https://www.deutschebank.co.in",
    # Government and regulatory
    "https://www.incometax.gov.in", "https://www.gst.gov.in",
    "https://www.uidai.gov.in", "https://www.india.gov.in",
    "https://www.mygov.in", "https://www.epfindia.gov.in",
    "https://www.nsdl.com", "https://www.cdsl.com",
    "https://www.sebi.gov.in", "https://www.irda.gov.in",
    # Payment platforms
    "https://www.paytm.com", "https://www.phonepe.com",
    "https://pay.google.com", "https://www.mobikwik.com",
    "https://www.freecharge.in", "https://www.bhimupi.org.in",
    # Insurance
    "https://www.licindia.in", "https://www.sbilife.co.in",
    "https://www.iciciprulife.com", "https://www.hdfclife.com",
    # Stock trading
    "https://www.zerodha.com", "https://www.upstox.com",
    "https://www.angelone.in", "https://groww.in",
    # Major Indian tech / ecommerce
    "https://www.flipkart.com", "https://www.amazon.in",
    "https://www.myntra.com", "https://www.swiggy.com",
    "https://www.zomato.com", "https://www.makemytrip.com",
    "https://www.irctc.co.in", "https://www.jio.com",
    "https://www.airtel.in", "https://www.vodafone.in",
]

# Curated legitimate URLs with realistic paths -- teaches the model
# that deep paths on real sites are normal, not phishing signals
LEGITIMATE_URLS_WITH_PATHS = [
    # Major global sites with paths
    "https://www.google.com/search?q=sbi+banking",
    "https://www.google.com/maps",
    "https://www.google.com/about",
    "https://www.google.com/intl/en/about/products",
    "https://www.github.com/user/repository",
    "https://www.github.com/login",
    "https://www.github.com/features/actions",
    "https://www.wikipedia.org/wiki/State_Bank_of_India",
    "https://www.wikipedia.org/wiki/YONO",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://stackoverflow.com/questions/12345",
    "https://stackoverflow.com/tags/python",
    "https://www.amazon.in/dp/product/B08XYZ",
    "https://www.amazon.in/gp/cart/view.html",
    "https://www.flipkart.com/mobiles/samsung/pr",
    "https://www.flipkart.com/account/login",
    "https://www.python.org/downloads/release/python-312",
    "https://www.python.org/about/gettingstarted",
    "https://www.microsoft.com/en-in/windows",
    "https://www.apple.com/in/iphone",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.linkedin.com/in/profile",
    "https://www.reddit.com/r/programming",
    # Indian banking legitimate URLs with paths
    "https://www.sbi.co.in/web/personal-banking/accounts",
    "https://www.sbi.co.in/web/personal-banking/loans/home-loan",
    "https://www.sbi.co.in/web/interest-rates/deposit-rates",
    "https://yono.sbi/home/dashboard",
    "https://onlinesbi.sbi/onlinesbi/do/login",
    "https://retail.onlinesbi.sbi/retail/login.htm",
    "https://www.hdfcbank.com/personal/pay/cards/credit-cards",
    "https://www.hdfcbank.com/personal/borrow/loans/home-loan",
    "https://www.hdfcbank.com/personal/save/accounts/savings-accounts",
    "https://www.icicibank.com/personal-banking/accounts/savings-account",
    "https://www.icicibank.com/personal-banking/loans/home-loan",
    "https://www.axisbank.com/retail/accounts/savings-account",
    "https://www.axisbank.com/retail/cards/credit-card",
    "https://www.kotak.com/en/personal-banking/accounts.html",
    "https://www.rbi.org.in/scripts/BS_ViewMasCirculardetails.aspx",
    "https://www.rbi.org.in/scripts/PublicationsView.aspx",
    "https://www.npci.org.in/what-we-do/upi/product-overview",
    "https://www.npci.org.in/what-we-do/imps/product-overview",
    # Government and institutional
    "https://www.incometax.gov.in/iec/foportal/help/individual",
    "https://www.uidai.gov.in/en/my-aadhaar/get-aadhaar.html",
    "https://www.irctc.co.in/nget/train-search",
    "https://www.digilocker.gov.in/dashboard",
    "https://www.gst.gov.in/help/returns",
    "https://www.epfindia.gov.in/site_en/index.php",
    # Payment platforms with paths
    "https://www.paytm.com/recharge",
    "https://www.phonepe.com/app/send-money",
    "https://www.zerodha.com/varsity/module/1",
    "https://groww.in/mutual-funds/best-mutual-funds",
]


# =========================================================================
# RBI .bank.in Domain Data (v1.1.0)
# After October 2025, all Indian banks operate on .bank.in domains.
# These curated URLs teach the model about the new domain namespace.
# =========================================================================

# Verified legitimate .bank.in URLs -- these are IDRBT-registered domains.
# The model must learn that .bank.in = strong trust signal (label 0).
BANK_IN_LEGITIMATE_URLS = [
    # SBI .bank.in -- largest Indian bank
    "https://sbi.bank.in",
    "https://sbi.bank.in/personal-banking",
    "https://sbi.bank.in/personal-banking/accounts/savings-account",
    "https://sbi.bank.in/personal-banking/loans/home-loan",
    "https://sbi.bank.in/nri-services",
    "https://sbi.bank.in/corporate-banking",
    "https://sbi.bank.in/interest-rates/deposit-rates",
    "https://onlinesbi.sbi.bank.in/personal/login",
    "https://onlinesbi.sbi.bank.in/personal/dashboard",
    # HDFC .bank.in
    "https://hdfc.bank.in",
    "https://hdfc.bank.in/personal/pay/cards/credit-cards",
    "https://hdfc.bank.in/personal/borrow/loans/home-loan",
    "https://hdfc.bank.in/personal/save/accounts/savings-accounts",
    "https://v.hdfc.bank.in/netbanking",
    # ICICI .bank.in
    "https://icici.bank.in",
    "https://icici.bank.in/personal-banking/accounts/savings-account",
    "https://icici.bank.in/personal-banking/loans/home-loan",
    "https://icici.bank.in/corporate/cash-management",
    # Axis .bank.in
    "https://axis.bank.in",
    "https://axis.bank.in/retail/accounts/savings-account",
    "https://axis.bank.in/retail/cards/credit-card",
    # Kotak .bank.in
    "https://kotak.bank.in",
    "https://kotak.bank.in/personal-banking/accounts",
    # Other major banks
    "https://pnb.bank.in",
    "https://pnb.bank.in/personal-banking/accounts",
    "https://ibanking.pnb.bank.in/login",
    "https://bankofbaroda.bank.in",
    "https://bankofbaroda.bank.in/personal-banking",
    "https://canarabank.bank.in",
    "https://canarabank.bank.in/personal-banking/loans",
    "https://unionbankofindia.bank.in",
    "https://bankofindia.bank.in",
    "https://indianbank.bank.in",
    "https://centralbank.bank.in",
    "https://idbi.bank.in",
    "https://idbi.bank.in/personal-banking",
    "https://iob.bank.in",
    "https://federal.bank.in",
    "https://yes.bank.in",
    "https://rbl.bank.in",
    "https://idfcfirst.bank.in",
    "https://idfcfirst.bank.in/personal-banking/accounts",
    "https://indusind.bank.in",
    "https://indusind.bank.in/personal/accounts",
]

# Curated .bank.in lookalike phishing URLs -- patterns attackers actually use
# to exploit the .bank.in migration confusion. Label 1 (phishing).
BANK_IN_PHISHING_URLS = [
    # Hyphen insertion attacks -- bank-in instead of bank.in
    "http://sbi.bank-in.com/login",
    "http://hdfc.bank-in.com/netbanking",
    "http://icici.bank-in.xyz/verify",
    "http://axis.bank-in.pw/kyc-update",
    "http://kotak.bank-in.net/secure-login",
    "http://sbi-bank-in-secure.xyz/auth",
    "http://hdfc-bank-in-login.com/verify",
    # Subdomain abuse -- .bank.in as subdomain not TLD
    "http://sbi.bank.in.phishing-site.xyz/login",
    "http://hdfc.bank.in.evil-domain.com/netbanking",
    "http://icici.bank.in.kyc-update.pw/verify",
    "http://axis.bank.in.secure-portal.xyz/auth",
    "http://pnb.bank.in.login-now.com/dashboard",
    # No-dot concatenation -- bankin instead of bank.in
    "http://sbibankin-login.com/verify",
    "http://hdfcbankin.xyz/netbanking",
    "http://icicibankin-secure.pw/kyc",
    "http://bankin-sbi-update.xyz/auth",
    # Underscore mimicry
    "http://sbi_bank_in.xyz/login",
    "http://hdfc_bank_in.com/verify",
    # TLD impersonation -- .bank.com, .bank.net
    "http://sbi.bank.com/login",
    "http://hdfc.bank.net/netbanking",
    "http://icici.bank.org/verify",
    # General post-migration confusion phishing
    "http://sbi-bank-in-migration.xyz/verify",
    "http://bank-in-update-sbi.pw/kyc",
    "http://hdfc-new-bank-in.xyz/login",
    "http://sbi-bank-in-activate.com/urgent",
    "http://bank-in-verify-icici.pw/account",
    # Existing-style phishing that now also triggers claims_bank_wrong_domain
    "http://sbi-kyc-migration.xyz/verify",
    "http://sbi-bank-login-secure.xyz/portal",
    "http://yono-sbi-update.pw/kyc",
    "http://hdfc-netbanking-update.xyz/verify",
    "http://icici-account-verify.pw/login",
    "http://axis-bank-secure.xyz/auth",
    "http://kotak-kyc-update.pw/verify",
    "http://pnb-netbanking-login.xyz/portal",
]

# Common path patterns for augmenting bare domains -- seed 42
_AUGMENTATION_PATHS = [
    "/",
    "/about",
    "/contact",
    "/search?q=banking",
    "/products/category",
    "/blog/2025/03",
    "/help/faq",
    "/login",
    "/account/settings",
    "/news/latest",
    "/wiki/article",
    "/docs/getting-started",
    "/api/v1/status",
    "/user/profile",
    "/en/home",
    "/terms",
    "/privacy-policy",
    "/support/tickets",
    "/downloads/latest",
    "/careers",
    "/press/releases",
    "/investors/reports",
    "/portal/dashboard",
    "/services/overview",
    "/resources/guides",
]


def _augment_domains_with_paths(domains: list, seed: int = 42, max_paths_per_domain: int = 3) -> list:
    """
    Generate path-augmented URL variants from bare domains.

    For each domain, generates 1-max_paths_per_domain URL variants
    with realistic paths. This teaches the model that legitimate
    sites also have deep paths, login pages, etc.

    Uses a fixed seed for reproducibility (seed=42).
    """
    rng = random.Random(seed)
    augmented = []

    for domain in domains:
        # keep the bare domain version too
        augmented.append(f"https://{domain}")

        # pick 1-3 random paths for this domain
        n_paths = rng.randint(1, max_paths_per_domain)
        chosen_paths = rng.sample(_AUGMENTATION_PATHS, min(n_paths, len(_AUGMENTATION_PATHS)))

        for path in chosen_paths:
            augmented.append(f"https://{domain}{path}")

    return augmented


# =========================================================================
# Download Functions
# =========================================================================

def download_phishtank(output_dir: str) -> list:
    """Download PhishTank verified phishing URLs."""
    url = "http://data.phishtank.com/data/online-valid.json.gz"
    output_file = os.path.join(output_dir, "phishtank.json.gz")
    urls = []

    logger.info("Downloading PhishTank dataset...")
    try:
        resp = requests.get(url, timeout=120, headers={"User-Agent": "phishtank/bankguard-ml"})
        if resp.status_code == 200:
            with open(output_file, "wb") as f:
                f.write(resp.content)
            # Parse
            data = json.loads(gzip.decompress(resp.content).decode("utf-8", errors="replace"))
            for entry in data:
                if entry.get("verified") == "yes":
                    u = entry.get("url", "").strip()
                    if u:
                        urls.append(u)
            logger.info(f"PhishTank: {len(urls)} verified phishing URLs")
        else:
            logger.warning(f"PhishTank download failed: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"PhishTank download error: {e}")

    return urls


def download_openphish(output_dir: str) -> list:
    """Download OpenPhish active phishing feed."""
    url = "https://openphish.com/feed.txt"
    output_file = os.path.join(output_dir, "openphish_feed.txt")
    urls = []

    logger.info("Downloading OpenPhish feed...")
    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 200:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(resp.text)
            urls = [line.strip() for line in resp.text.splitlines() if line.strip()]
            logger.info(f"OpenPhish: {len(urls)} phishing URLs")
        else:
            logger.warning(f"OpenPhish download failed: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"OpenPhish download error: {e}")

    return urls


def download_phishing_database(output_dir: str) -> list:
    """Download Phishing.Database active URLs from GitHub."""
    base = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    output_file = os.path.join(output_dir, "phishing_database_active.txt")
    urls = []

    logger.info("Downloading Phishing.Database...")
    try:
        resp = requests.get(base, timeout=120)
        if resp.status_code == 200:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(resp.text)
            urls = [line.strip() for line in resp.text.splitlines()
                    if line.strip() and not line.startswith("#")]
            logger.info(f"Phishing.Database: {len(urls)} active phishing URLs")
        else:
            logger.warning(f"Phishing.Database download failed: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"Phishing.Database download error: {e}")

    return urls


def download_tranco(output_dir: str, sample_size: int = 100000) -> list:
    """
    Download Tranco Top 1 Million legitimate domains.

    Returns path-augmented URLs -- each domain gets 1-3 additional
    URL variants with realistic paths to teach the model that
    legitimate sites also have deep paths.
    """
    url = "https://tranco-list.eu/download/6Q2VJ/1000000"
    output_file = os.path.join(output_dir, "tranco_top1m.csv")
    urls = []

    if os.path.exists(output_file):
        logger.info("Tranco Top 1M list already exists, using local file.")
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                all_domains = []
                for row in reader:
                    if len(row) >= 2:
                        domain = row[1].strip()
                        if domain:
                            all_domains.append(domain)
                # Sample bare domains first, then augment with paths
                if len(all_domains) > sample_size:
                    sampled = random.sample(all_domains, sample_size)
                else:
                    sampled = all_domains
                urls = _augment_domains_with_paths(sampled, seed=RANDOM_SEED)
                logger.info(f"Tranco: {len(sampled)} domains sampled, {len(urls)} URLs after path augmentation (from local file)")
        except Exception as e:
            logger.warning(f"Tranco local file read error: {e}")
        return urls

    logger.info("Downloading Tranco Top 1M list...")
    try:
        resp = requests.get(url, timeout=120)
        if resp.status_code == 200:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(resp.text)
            reader = csv.reader(io.StringIO(resp.text))
            all_domains = []
            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip()
                    if domain:
                        all_domains.append(domain)
            # Sample
            if len(all_domains) > sample_size:
                sampled = random.sample(all_domains, sample_size)
            else:
                sampled = all_domains
            urls = _augment_domains_with_paths(sampled, seed=RANDOM_SEED)
            logger.info(f"Tranco: {len(sampled)} domains sampled, {len(urls)} URLs after path augmentation")
        else:
            logger.warning(f"Tranco download failed: HTTP {resp.status_code}")
    except Exception as e:
        logger.warning(f"Tranco download error: {e}")

    return urls


# =========================================================================
# Cleaning
# =========================================================================

def get_tranco_top10k(output_dir: str) -> set:
    """Load top 10k domains from the Tranco list for false positive filtering."""
    path = os.path.join(output_dir, "tranco_top1m.csv")
    domains = set()
    if not os.path.exists(path):
        return domains
    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i >= 10000:
                    break
                if len(row) >= 2:
                    domains.add(row[1].strip().lower())
    except Exception:
        pass
    return domains


def normalize_url(url: str) -> str:
    """Normalize URL: lowercase scheme + domain, preserve path case."""
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or ""
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        return f"{scheme}://{netloc}{path}{query}{fragment}"
    except Exception:
        return url.strip()


def clean_dataset(phishing_urls: list, legit_urls: list, tranco_top10k: set) -> list:
    """
    Clean and deduplicate the entire dataset.
    Returns list of (url, label, source) tuples.
    """
    seen = set()
    cleaned = []

    def add_url(url: str, label: int, source: str):
        url = url.strip()
        if not url or len(url) > 500:
            return
        normalized = normalize_url(url)
        url_hash = hashlib.md5(normalized.encode()).hexdigest()
        if url_hash in seen:
            return
        seen.add(url_hash)

        # Remove phishing URLs that match top 10k legitimate domains
        if label == 1:
            try:
                domain = urlparse(normalized).netloc.lower()
                if domain in tranco_top10k:
                    return
            except Exception:
                pass

        cleaned.append((normalized, label, source))

    for url in phishing_urls:
        add_url(url, 1, "phishtank+openphish+phishdb")
    for url in legit_urls:
        add_url(url, 0, "tranco+curated")

    return cleaned


def balance_dataset(data: list, target_phishing_ratio: float = 0.6) -> list:
    """Balance dataset to target ratio (60% phishing, 40% legitimate)."""
    phishing = [x for x in data if x[1] == 1]
    legit = [x for x in data if x[1] == 0]

    logger.info(f"Before balancing: {len(phishing)} phishing, {len(legit)} legitimate")

    # Calculate target counts
    total = len(phishing) + len(legit)
    target_phishing = int(total * target_phishing_ratio)
    target_legit = total - target_phishing

    # Subsample the larger class
    if len(phishing) > target_phishing:
        phishing = random.sample(phishing, target_phishing)
    if len(legit) > target_legit:
        legit = random.sample(legit, target_legit)

    balanced = phishing + legit
    random.shuffle(balanced)

    logger.info(f"After balancing: {len([x for x in balanced if x[1]==1])} phishing, "
                f"{len([x for x in balanced if x[1]==0])} legitimate")

    return balanced


# =========================================================================
# Main
# =========================================================================

def main():
    os.makedirs(RAW_DIR, exist_ok=True)
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # --- Collect Phishing URLs ---
    phishing_urls = []

    pt_urls = download_phishtank(RAW_DIR)
    phishing_urls.extend(pt_urls)

    op_urls = download_openphish(RAW_DIR)
    phishing_urls.extend(op_urls)

    pdb_urls = download_phishing_database(RAW_DIR)
    phishing_urls.extend(pdb_urls)

    india_urls = _expand_india_urls(INDIA_PHISHING_URLS)
    phishing_urls.extend(india_urls)
    logger.info(f"India-specific curated: {len(india_urls)} phishing URLs")

    # v1.1.0 -- .bank.in lookalike phishing patterns
    phishing_urls.extend(BANK_IN_PHISHING_URLS)
    logger.info(f".bank.in lookalike phishing: {len(BANK_IN_PHISHING_URLS)} URLs")

    logger.info(f"Total raw phishing URLs: {len(phishing_urls)}")

    # --- Collect Legitimate URLs ---
    legit_urls = []

    tranco_urls = download_tranco(RAW_DIR)
    legit_urls.extend(tranco_urls)

    legit_urls.extend(INDIA_LEGITIMATE_URLS)
    logger.info(f"India legitimate curated: {len(INDIA_LEGITIMATE_URLS)} URLs")

    # High-value legitimate URLs with real paths -- critical for
    # teaching the model that deep paths on real sites are normal
    legit_urls.extend(LEGITIMATE_URLS_WITH_PATHS)
    logger.info(f"Legitimate URLs with paths: {len(LEGITIMATE_URLS_WITH_PATHS)} URLs")

    # v1.1.0 -- verified .bank.in domains with path variants
    legit_urls.extend(BANK_IN_LEGITIMATE_URLS)
    logger.info(f".bank.in verified legitimate: {len(BANK_IN_LEGITIMATE_URLS)} URLs")

    logger.info(f"Total raw legitimate URLs: {len(legit_urls)}")

    # --- Clean and Balance ---
    tranco_top10k = get_tranco_top10k(RAW_DIR)
    cleaned = clean_dataset(phishing_urls, legit_urls, tranco_top10k)
    logger.info(f"Total after cleaning: {len(cleaned)}")

    balanced = balance_dataset(cleaned)

    # --- Save ---
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "source"])
        for url, label, source in balanced:
            writer.writerow([url, label, source])

    # Stats
    labels = Counter(x[1] for x in balanced)
    logger.info(f"Saved {len(balanced)} samples to {OUTPUT_CSV}")
    logger.info(f"  Phishing (1): {labels[1]} ({labels[1]/len(balanced)*100:.1f}%)")
    logger.info(f"  Legitimate (0): {labels[0]} ({labels[0]/len(balanced)*100:.1f}%)")


if __name__ == "__main__":
    main()
