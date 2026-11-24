"""
Three-Tier Trusted Domain Whitelist for BankGuard Phishing Detection.

Implements the RBI .bank.in domain mandate (April 2025 circular, deadline
October 31 2025). All Indian banks have completed migration to .bank.in
domains registered through IDRBT/NIXI/MeitY.

Tier 1: RBI-regulated .bank.in domains (maximum trust, IDRBT-verified)
Tier 2: Legacy banking domains still active (high trust, redirecting to .bank.in)
Tier 3: General trusted domains (non-banking, never-flag)

Security note: Only exact hostname matching is used. Substring and
suffix matching are intentionally avoided to prevent bypass via
lookalike domains like sbi.bank.in.phishing.xyz

Used at:
  1. Feature engineering (claims_bank_wrong_domain feature)
  2. Export sanity check (tier-aware whitelist override)
  3. Backend inference wrapper (instant SAFE bypass)
"""

from urllib.parse import urlparse


# =========================================================================
# Tier 1 -- Maximum Trust (.bank.in verified domains)
# RBI-regulated, IDRBT-registered. No fraudster can register these.
# Source: confirmed from IDRBT migration announcements + bank press releases
# =========================================================================

# fmt: off
TIER_1_BANK_IN_DOMAINS = {
    # Major public sector banks
    "sbi.bank.in",
    "onlinesbi.sbi.bank.in",
    "pnb.bank.in",
    "ibanking.pnb.bank.in",
    "bankofbaroda.bank.in",
    "canarabank.bank.in",
    "unionbankofindia.bank.in",
    "bankofindia.bank.in",
    "indianbank.bank.in",
    "centralbank.bank.in",
    "uco.bank.in",
    "idbi.bank.in",
    "bankofmaharashtra.bank.in",
    "punjabandsind.bank.in",
    "iob.bank.in",

    # Major private sector banks
    "hdfc.bank.in",
    "v.hdfc.bank.in",
    "icici.bank.in",
    "axis.bank.in",
    "kotak.bank.in",
    "indusind.bank.in",
    "yes.bank.in",
    "federal.bank.in",
    "rbl.bank.in",
    "idfcfirst.bank.in",
    "csb.bank.in",
    "southindianbank.bank.in",
    "kvb.bank.in",
    "dhan.bank.in",
    "esaf.bank.in",

    # Regional and cooperative
    "keralabank.bank.in",
    "kgb.bank.in",
}
# fmt: on


# =========================================================================
# Tier 2 -- Legacy Trust (old domains, still active, redirecting to .bank.in)
# Legitimate but officially deprecated for banking. Millions of existing
# bookmarks and app links still reference these.
# =========================================================================

# fmt: off
TIER_2_LEGACY_DOMAINS = {
    # RBI and financial infrastructure -- regulatory bodies
    "rbi.org.in", "www.rbi.org.in",
    "npci.org.in", "www.npci.org.in",
    "idrbt.ac.in", "www.idrbt.ac.in",
    "upi.org.in", "www.upi.org.in",
    "upichalega.com", "www.upichalega.com",
    "api.npci.org.in",

    # SBI legacy & branches
    "sbi.co.in", "www.sbi.co.in",
    "onlinesbi.sbi", "retail.onlinesbi.sbi",
    "yono.sbi",
    "sbiyono.sbi",
    "retail.onlinesbi.com",
    "sbifreedom.in", "www.sbifreedom.in",
    "statebankofindia.com", "www.statebankofindia.com",
    "sbicard.com", "www.sbicard.com",
    "sbilife.co.in", "www.sbilife.co.in",
    "sbimf.com", "www.sbimf.com",
    "yonobusiness.sbi",
    "merchant.sbi",
    "sbiepay.sbi",
    "sbiloans.sbi",
    "sbismart.com", "www.sbismart.com",
    "sbigeneral.in", "www.sbigeneral.in",
    "static.onlinesbi.sbi",

    # HDFC legacy & branches
    "hdfcbank.com", "www.hdfcbank.com",
    "netbanking.hdfcbank.com",
    "netportal.hdfcbank.com",
    "hdfc.com", "www.hdfc.com",
    "hdfcbankmarks.com", "www.hdfcbankmarks.com",
    "smartbuy.hdfcbank.com",
    "mycards.hdfcbank.com",
    "v1.hdfcbank.com",
    "apply.hdfcbank.com",
    "offers.smartbuy.hdfcbank.com",
    "hdfcbk.io",
    "hdfcbank.onelink.me",
    "hdfcbank.net", "www.hdfcbank.net",
    "m.hdfcbank.com",
    "merchant.hdfcbank.com",
    "payzapp.hdfcbank.com",
    "homerang.hdfcbank.com",
    "zipdrive.hdfcbank.com",
    "hdfcergo.com", "www.hdfcergo.com",
    "hdfclife.com", "www.hdfclife.com",
    "hdfcsec.com", "www.hdfcsec.com",
    "hdfcfund.com", "www.hdfcfund.com",
    "api.hdfcbank.com",
    "developer.hdfcbank.com",
    "static.hdfcbank.com",

    # ICICI legacy & branches
    "icicibank.com", "www.icicibank.com",
    "infinityicicibank.com",
    "icici.com", "www.icici.com",
    "icicibank.co.in", "www.icicibank.co.in",
    "icicipruamc.com", "www.icicipruamc.com",
    "icicidirect.com", "www.icicidirect.com",
    "loans.icicibank.com",
    "cards.icicibank.com",
    "icici.im",
    "icicibank.onelink.me",
    "infinity.icicibank.com",
    "cib.icicibank.com",
    "imobile.icicibank.com",
    "merchant.icicibank.com",
    "elections.icicibank.com",
    "express.icicibank.com",
    "iciciprulife.com", "www.iciciprulife.com",
    "icicilombard.com", "www.icicilombard.com",
    "api.icicibank.com",
    "developer.icicibank.com",
    "m.icicibank.com",

    # Axis legacy & branches
    "axisbank.com", "www.axisbank.com",
    "uti-bank.com", "www.uti-bank.com",
    "axisbank.co.in", "www.axisbank.co.in",
    "axisdirect.in", "www.axisdirect.in",
    "grabdeals.axisbank.com",
    "digital.axisbank.com",
    "axisbank.onelink.me",
    "corporate.axisbank.co.in",
    "retail.axisbank.co.in",
    "merchant.axisbank.com",
    "maxlifeinsurance.com", "www.maxlifeinsurance.com",
    "axismf.com", "www.axismf.com",
    "api.axisbank.com",

    # Kotak legacy
    "kotak.com", "www.kotak.com",

    # PNB legacy
    "pnbindia.in", "www.pnbindia.in",

    # Other major banks legacy
    "canarabank.com", "www.canarabank.com",
    "unionbankofindia.co.in", "www.unionbankofindia.co.in",
    "bankofbaroda.in", "www.bankofbaroda.in",
    "centralbankofindia.co.in", "www.centralbankofindia.co.in",
    "indianbank.in", "www.indianbank.in",
    "bankofindia.co.in", "www.bankofindia.co.in",
    "idbibank.in", "www.idbibank.in",
    "iob.in",
    "federalbank.co.in", "www.federalbank.co.in",
    "indusind.com", "www.indusind.com",
    "yesbank.in", "www.yesbank.in",
    "rblbank.com",
    "idfcfirstbank.com",

    # AU Small Finance Bank
    "apply.aubank.in",
    "netbanking.aubank.in",
    "api.aubank.in",

    # Payment infrastructure
    "bhimupi.org.in", "www.bhimupi.org.in",
    "paytm.com", "www.paytm.com",
    "phonepe.com", "www.phonepe.com",
    "gpay.app",
    "mobikwik.com", "www.mobikwik.com",
    "paytmbank.com", "www.paytmbank.com",
    "paytm.in", "www.paytm.in",
    "paytmmoney.com", "www.paytmmoney.com",
    "developer.paytm.com",
    "assetscdn1.paytm.com",
    "securegw.paytm.in",
    "dashboard.paytm.com",
    "p-y.tm",
}
# fmt: on


# =========================================================================
# Tier 3 -- General Trusted (non-banking legitimate domains)
# Never flag regardless of model score. No banking domains here.
# =========================================================================

# fmt: off
TIER_3_GENERAL_TRUSTED = {
    # Major global platforms
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "wikipedia.org", "www.wikipedia.org",
    "en.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
    "amazon.in", "www.amazon.in",
    "amazon.com", "www.amazon.com",
    "flipkart.com", "www.flipkart.com",
    "python.org", "www.python.org",
    "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com",
    "youtube.com", "www.youtube.com",
    "linkedin.com", "www.linkedin.com",
    "twitter.com", "www.twitter.com",
    "x.com", "www.x.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "reddit.com", "www.reddit.com",

    # Indian government
    "incometax.gov.in", "www.incometax.gov.in",
    "uidai.gov.in", "www.uidai.gov.in",
    "irctc.co.in", "www.irctc.co.in",
    "digilocker.gov.in", "www.digilocker.gov.in",
    "india.gov.in", "www.india.gov.in",
    "mha.gov.in", "www.mha.gov.in",
    "cybercrime.gov.in", "www.cybercrime.gov.in",
    "sancharsaathi.gov.in", "www.sancharsaathi.gov.in",
    "gst.gov.in", "www.gst.gov.in",
    "epfindia.gov.in", "www.epfindia.gov.in",
    "sebi.gov.in", "www.sebi.gov.in",

    # Insurance and stock
    "licindia.in", "www.licindia.in",
    "sbilife.co.in", "www.sbilife.co.in",
    "zerodha.com", "www.zerodha.com",
    "groww.in",

    # Indian ecommerce / tech
    "myntra.com", "www.myntra.com",
    "swiggy.com", "www.swiggy.com",
    "zomato.com", "www.zomato.com",
    "makemytrip.com", "www.makemytrip.com",
    "jio.com", "www.jio.com",
    "airtel.in", "www.airtel.in",
}
# fmt: on


def _extract_hostname(url: str) -> str:
    """Parse URL and return lowercase hostname with port and 'www.' stripped."""
    if not url:
        return ""
    url_lower = url.lower().strip()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        url_lower = "http://" + url_lower
    try:
        parsed = urlparse(url_lower)
        hostname = (parsed.hostname or "").strip().strip(".")
        # Strip 'www.' prefix for consistent matching
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname
    except Exception:
        return ""


def get_domain_trust_tier(url: str) -> int:
    """
    Returns the trust tier of a URL's domain:
      1 = Tier 1 (.bank.in verified, maximum trust - IDRBT-registered)
      2 = Tier 2 (legacy banking domain, high trust - still active, redirects)
      3 = Tier 3 (general trusted domain - non-banking, never-flag)
      0 = Not in any trusted tier

    Uses exact hostname matching only - never substring matching.
    Port numbers are stripped before matching.
    """
    hostname = _extract_hostname(url)
    if not hostname:
        return 0

    if hostname in TIER_1_BANK_IN_DOMAINS:
        return 1
    if hostname in TIER_2_LEGACY_DOMAINS:
        return 2
    if hostname in TIER_3_GENERAL_TRUSTED:
        return 3
    return 0


def is_trusted_domain(url: str) -> bool:
    """
    Returns True if the URL's domain is in any trust tier.
    Backward-compatible wrapper around get_domain_trust_tier().
    """
    return get_domain_trust_tier(url) > 0
