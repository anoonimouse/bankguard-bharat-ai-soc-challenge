"""
Seed script for the FRI (Financial Fraud Risk Indicator) database.
Generates 500+ realistic synthetic fraudster entries with varied Indian identifiers.

Run once:  python seed_fri.py
"""

import random
import string
import sys
import os

# Ensure we can import sibling modules
sys.path.insert(0, os.path.dirname(__file__))

from database import engine, SessionLocal, Base
from models import FriEntry, FriIdentifier

# ---------- Configuration ----------

TOTAL_ENTRIES = 550

RISK_LEVELS = ["High"] * 40 + ["Very High"] * 35 + ["Medium"] * 25  # weighted pool

FRAUD_CATEGORIES_WEIGHTED = (
    ["UPI Fraud"] * 25
    + ["Fake KYC"] * 20
    + ["OTP Theft"] * 12
    + ["Phishing"] * 12
    + ["Vishing"] * 10
    + ["Account Takeover"] * 8
    + ["Fake Rewards"] * 7
    + ["SIM Swap"] * 6
)

UPI_HANDLES = [
    "@paytm", "@ybl", "@okaxis", "@okhdfcbank", "@oksbi",
    "@ibl", "@axl", "@upi", "@apl", "@ikwik",
]

EMAIL_DOMAINS = [
    "gmail.com", "yahoo.co.in", "rediffmail.com", "outlook.com",
    "hotmail.com", "yahoo.com", "protonmail.com",
]

SOCIAL_PLATFORMS = ["whatsapp", "telegram", "instagram", "facebook"]

FIRST_NAMES = [
    "rahul", "priya", "amit", "sunita", "vijay", "deepak", "neha", "suresh",
    "pooja", "rajesh", "anita", "manoj", "kavita", "sanjay", "ritu",
    "arun", "geeta", "mohan", "rekha", "ashok", "meena", "vinod",
    "sandhya", "pankaj", "nisha", "mukesh", "seema", "ravi", "swati",
    "harish", "divya", "sunil", "jyoti", "pramod", "shobha", "devendra",
    "lakshmi", "gopal", "aarti", "naveen", "komal", "vikram", "sneha",
    "prakash", "mamta", "ramesh", "shalini", "dinesh", "uma", "nitin",
]

LAST_NAMES = [
    "sharma", "kumar", "singh", "patel", "gupta", "verma", "joshi",
    "yadav", "reddy", "nair", "iyer", "das", "mehta", "chauhan",
    "mishra", "pandey", "thakur", "saxena", "dubey", "tiwari",
    "jain", "agarwal", "banerjee", "mukherjee", "srinivasan",
    "pillai", "menon", "rajan", "kaur", "bhat", "hegde", "naidu",
]

REASON_TEMPLATES = {
    "UPI Fraud": [
        "Linked to multiple UPI fraud complaints on NPCI portal",
        "Involved in collect-request scam targeting SBI customers",
        "Reported for fraudulent UPI refund reversal scheme",
        "Associated with fake merchant QR code distribution",
    ],
    "Fake KYC": [
        "Operated fake KYC update portal impersonating SBI",
        "Sent mass SMS with fraudulent KYC expiry links",
        "Collected Aadhaar and PAN data through fake KYC form",
        "Impersonated SBI customer service for KYC verification",
    ],
    "OTP Theft": [
        "Used social engineering to extract OTPs from victims",
        "Operated call center targeting elderly for OTP extraction",
        "Installed screen-sharing apps on victims' devices for OTP theft",
        "Tricked victims into forwarding SMS containing OTPs",
    ],
    "Phishing": [
        "Distributed phishing links mimicking SBI YONO login",
        "Operated lookalike banking domain for credential harvesting",
        "Sent bulk emails with malicious SBI-themed attachments",
        "Created fake SBI reward claim pages to steal credentials",
    ],
    "Vishing": [
        "Impersonated SBI branch manager in phone calls",
        "Called victims claiming their account was compromised",
        "Used spoofed caller ID to appear as SBI helpline",
        "Conducted voice-based social engineering for card details",
    ],
    "Account Takeover": [
        "Gained unauthorized access to multiple SBI accounts",
        "Used stolen credentials to transfer funds illegally",
        "Changed registered mobile numbers on compromised accounts",
        "Performed unauthorized NEFT transfers from hijacked accounts",
    ],
    "Fake Rewards": [
        "Sent fake SBI cashback/reward messages to lure victims",
        "Operated fraudulent lucky draw scheme in SBI's name",
        "Distributed fake festival bonus links on social media",
        "Created fake SBI reward points redemption portal",
    ],
    "SIM Swap": [
        "Obtained duplicate SIM to intercept OTPs",
        "Colluded with telecom agent for unauthorized SIM replacement",
        "Used forged documents for SIM swap at retail outlet",
        "Executed SIM swap attack to take over mobile banking",
    ],
}

# ---------- Helpers ----------

def random_mobile():
    """Generate realistic Indian mobile number (10 digits, starts with 6/7/8/9)."""
    first = random.choice(["6", "7", "8", "9"])
    rest = "".join(random.choices(string.digits, k=9))
    return first + rest


def random_upi(first_name, last_name):
    """Generate realistic UPI ID."""
    handle = random.choice(UPI_HANDLES)
    patterns = [
        f"{first_name}{last_name}{random.randint(1, 999)}{handle}",
        f"{first_name}.{last_name}{handle}",
        f"{first_name}{random.randint(10, 99)}{handle}",
        f"{last_name}.{first_name}{handle}",
        f"{first_name}{last_name[0]}{random.randint(1, 9999)}{handle}",
    ]
    return random.choice(patterns).lower()


def random_email(first_name, last_name):
    """Generate realistic Indian email address."""
    domain = random.choice(EMAIL_DOMAINS)
    patterns = [
        f"{first_name}.{last_name}{random.randint(1, 999)}@{domain}",
        f"{first_name}{last_name}{random.randint(10, 9999)}@{domain}",
        f"{first_name}_{last_name}@{domain}",
        f"{last_name}.{first_name}{random.randint(1, 99)}@{domain}",
    ]
    return random.choice(patterns).lower()


def random_social(first_name, last_name):
    """Generate realistic social media handle."""
    platform = random.choice(SOCIAL_PLATFORMS)
    if platform == "whatsapp":
        return f"whatsapp:{random_mobile()}"
    elif platform == "telegram":
        return f"telegram:@{first_name}_{last_name}{random.randint(1, 999)}"
    elif platform == "instagram":
        return f"instagram:@{first_name}.{last_name}{random.randint(1, 99)}"
    else:
        return f"facebook:{first_name}.{last_name}.{random.randint(100, 99999)}"


def random_bank_account():
    """Generate realistic Indian bank account number (9-18 digits)."""
    length = random.choice([9, 10, 11, 12, 13, 14, 15, 16, 17, 18])
    return "".join(random.choices(string.digits, k=length))


# ---------- Main Seed Logic ----------

def seed():
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    # Check if already seeded
    existing = db.query(FriEntry).count()
    if existing > 0:
        print(f"FRI database already has {existing} entries. Skipping seed.")
        db.close()
        return

    print(f"Seeding {TOTAL_ENTRIES} FRI entries...")

    for i in range(TOTAL_ENTRIES):
        risk_level = random.choice(RISK_LEVELS)
        fraud_category = random.choice(FRAUD_CATEGORIES_WEIGHTED)
        reason = random.choice(REASON_TEMPLATES[fraud_category])

        first_name = random.choice(FIRST_NAMES)
        last_name = random.choice(LAST_NAMES)

        entry = FriEntry(
            risk_level=risk_level,
            fraud_category=fraud_category,
            reason=reason,
        )
        db.add(entry)
        db.flush()  # get entry.id

        # Decide which identifiers this entry gets (varied coverage)
        # Everyone gets a mobile number
        db.add(FriIdentifier(
            entry_id=entry.id,
            identifier_type="mobile",
            identifier_value=random_mobile(),
        ))

        # ~80% get a UPI ID
        if random.random() < 0.80:
            db.add(FriIdentifier(
                entry_id=entry.id,
                identifier_type="upi",
                identifier_value=random_upi(first_name, last_name),
            ))

        # ~50% get an email
        if random.random() < 0.50:
            db.add(FriIdentifier(
                entry_id=entry.id,
                identifier_type="email",
                identifier_value=random_email(first_name, last_name),
            ))

        # ~35% get a social handle
        if random.random() < 0.35:
            db.add(FriIdentifier(
                entry_id=entry.id,
                identifier_type="social",
                identifier_value=random_social(first_name, last_name),
            ))

        # ~40% get a bank account
        if random.random() < 0.40:
            db.add(FriIdentifier(
                entry_id=entry.id,
                identifier_type="bank_account",
                identifier_value=random_bank_account(),
            ))

    db.commit()
    db.close()

    print(f"✓ Successfully seeded {TOTAL_ENTRIES} FRI entries.")


if __name__ == "__main__":
    seed()
