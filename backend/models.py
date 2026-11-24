from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from database import Base
import datetime

class AdminUser(Base):
    """Dashboard administrator account with bcrypt-hashed password."""
    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class FraudReport(Base):
    __tablename__ = "fraud_reports"

    id = Column(Integer, primary_key=True, index=True)
    report_type = Column(String, index=True) # e.g. "URL", "APK", "SMS"
    source = Column(String) # e.g. "com.bankguard.app"
    content = Column(String) # the suspicious link or apk package name
    risk_score = Column(Float, default=0.0)
    scam_tactic = Column(String, nullable=True)
    status = Column(String, default="pending") # pending, verified, false_positive
    reported_at = Column(DateTime, default=datetime.datetime.utcnow)
    state_region = Column(String, nullable=True) # e.g. "Jharkhand", "Haryana", etc.

class SuspiciousDomain(Base):
    __tablename__ = "suspicious_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain_name = Column(String, unique=True, index=True)
    threat_level = Column(String) # HIGH, MEDIUM, LOW
    is_active = Column(Boolean, default=True)
    identified_at = Column(DateTime, default=datetime.datetime.utcnow)

class FriEntry(Base):
    """Financial Fraud Risk Indicator entry - represents a single fraudster profile."""
    __tablename__ = "fri_entries"

    id = Column(Integer, primary_key=True, index=True)
    risk_level = Column(String, index=True)       # Medium, High, Very High
    fraud_category = Column(String, index=True)    # UPI Fraud, Fake KYC, OTP Theft, etc.
    reason = Column(String)                        # Human-readable explanation
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    identifiers = relationship("FriIdentifier", back_populates="entry", lazy="joined")

class FriIdentifier(Base):
    """A single identifier (phone, UPI ID, email, etc.) linked to a FriEntry."""
    __tablename__ = "fri_identifiers"

    id = Column(Integer, primary_key=True, index=True)
    entry_id = Column(Integer, ForeignKey("fri_entries.id"), index=True)
    identifier_type = Column(String, index=True)   # mobile, upi, email, social, bank_account
    identifier_value = Column(String, index=True)   # the actual value

    entry = relationship("FriEntry", back_populates="identifiers")


class ActiveCallSession(Base):
    """Active outbound call sessions initiated by legitimate bank agents."""
    __tablename__ = "active_call_sessions"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, index=True, nullable=False)
    calling_number = Column(String, index=True, nullable=False)
    is_active = Column(Boolean, default=True)
    agent_name = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class UserDeviceProfile(Base):
    """Secure device binding profiles to prevent session hijacking and SIM swapping."""
    __tablename__ = "user_device_profiles"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, unique=True, index=True, nullable=False)
    device_key_pub = Column(String, nullable=False)  # Public key generated on device enrollment
    sim_hash_baseline = Column(String, nullable=False)  # Hash of baseline SIM details
    last_seen_ip = Column(String, nullable=True)
    last_active = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    is_locked = Column(Boolean, default=False)  # Set to true if a SIM swap or anomaly is detected
    shield_points = Column(Integer, default=0, nullable=False)
    redeemed_vouchers = Column(Text, default="[]", nullable=False)


class TelecomSimSwapRegistry(Base):
    """Simulated Telecom Registry to mock GSMA/Carrier SIM Swap API checks."""
    __tablename__ = "telecom_sim_swap_registry"

    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String, unique=True, index=True, nullable=False)
    sim_swapped_at = Column(DateTime, nullable=True)  # Timestamp of simulated SIM swap


class SilentSmsChallenge(Base):
    """Cryptographic Silent SMS nonces issued by the bank backend."""
    __tablename__ = "silent_sms_challenges"

    id = Column(Integer, primary_key=True, index=True)
    customer_id = Column(String, index=True, nullable=False)
    nonce = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String, default="pending")  # pending, verified, failed, expired

