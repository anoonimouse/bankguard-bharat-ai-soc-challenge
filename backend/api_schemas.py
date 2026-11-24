from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class URLCheckRequest(BaseModel):
    url: str

class MLFeatureImportance(BaseModel):
    feature: str
    importance: float

class MLAnalysis(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_confidence: int
    raw_probability: float
    top_features: list[MLFeatureImportance] = []
    threshold_used: float
    model_version: str = "1.0.0"

class URLCheckResponse(BaseModel):
    url: str
    is_safe: bool
    risk_score: float
    threat_type: Optional[str] = None
    message: str
    ml_analysis: Optional[MLAnalysis] = None

class APKVerifyRequest(BaseModel):
    package_name: str
    cert_hash: str

class APKVerifyResponse(BaseModel):
    package_name: str
    is_official: bool
    message: str

class FraudReportCreate(BaseModel):
    report_type: str
    source: str
    content: str
    risk_score: Optional[float] = 0.0
    state_region: Optional[str] = None

class FraudReportResponse(FraudReportCreate):
    id: int
    status: str
    reported_at: datetime

    class Config:
        from_attributes = True # updated for Pydantic V2

class SuspiciousDomainCreate(BaseModel):
    domain_name: str
    threat_level: Optional[str] = "HIGH"

class SuspiciousDomainResponse(BaseModel):
    id: int
    domain_name: str
    threat_level: str
    is_active: bool
    identified_at: datetime

    class Config:
        from_attributes = True

class CheckDetail(BaseModel):
    check_name: str
    status: str # "pass", "fail", "warn"
    message: str

class APKScanResponse(BaseModel):
    verdict: str # "safe", "suspicious", "malicious", "unrelated"
    risk_score: int # 1 to 100
    app_name: Optional[str] = None
    package_name: Optional[str] = None
    cert_hash: Optional[str] = None
    checks: list[CheckDetail] = []

# --- FRI (Fraud Risk Indicator) Schemas ---

class FriCheckRequest(BaseModel):
    identifier_type: str   # mobile, upi, email, social, bank_account
    identifier_value: str

class FriIdentifierResult(BaseModel):
    found: bool
    entry_id: Optional[int] = None
    risk_level: Optional[str] = None
    fraud_category: Optional[str] = None
    reason: Optional[str] = None

class FriBatchItem(BaseModel):
    identifier_type: str
    identifier_value: str

class FriBatchCheckRequest(BaseModel):
    identifiers: list[FriBatchItem]

class FriBatchResult(BaseModel):
    identifier_type: str
    identifier_value: str
    found: bool
    entry_id: Optional[int] = None
    risk_level: Optional[str] = None
    fraud_category: Optional[str] = None
    reason: Optional[str] = None

class FriBatchCheckResponse(BaseModel):
    results: list[FriBatchResult]

class FriIdentifierDetail(BaseModel):
    identifier_type: str
    identifier_value: str

    class Config:
        from_attributes = True

class FriEntryResponse(BaseModel):
    id: int
    risk_level: str
    fraud_category: str
    reason: str
    identifiers: list[FriIdentifierDetail] = []

    class Config:
        from_attributes = True


class ActiveCallResponse(BaseModel):
    active_call: bool
    agent_name: Optional[str] = None
    number_type: str


class DeviceBindRequest(BaseModel):
    customer_id: str
    device_key_pub: str
    sim_hash: str


class DeviceBindResponse(BaseModel):
    success: bool
    message: str


class DeviceVerifyRequest(BaseModel):
    customer_id: str
    sim_hash: str
    signature: str  # Mandatory signature to verify device binding integrity
    payload: str


class DeviceVerifyResponse(BaseModel):
    verified: bool
    is_locked: bool
    message: str


class DeviceReverifyRequest(BaseModel):
    customer_id: str
    sim_hash: str
    otp: str


class TransactionRequest(BaseModel):
    customer_id: str
    amount: float
    target_identifier: str
    identifier_type: str  # upi, mobile, bank_account
    signature: str        # ECDSA signature of transaction details


class TransactionResponse(BaseModel):
    success: bool
    transaction_id: Optional[str] = None
    message: str


class SimulateSwapRequest(BaseModel):
    phone_number: str
    hours_ago: Optional[int] = None  # None to clear, or integer of hours ago the swap occurred


class SimulateSwapResponse(BaseModel):
    success: bool
    phone_number: str
    swapped_at: Optional[datetime] = None
    message: str


class SilentSmsTriggerRequest(BaseModel):
    customer_id: str


class SilentSmsTriggerResponse(BaseModel):
    success: bool
    nonce: str
    expires_at: datetime
    message: str


class SilentSmsVerifyRequest(BaseModel):
    customer_id: str
    nonce: str
    signature: str  # Signed challenge response from device


class SilentSmsVerifyResponse(BaseModel):
    success: bool
    status: str
    message: str


class SilentSmsInvalidateRequest(BaseModel):
    customer_id: str
    nonce: str


# --- Chakshu Portal Integration Schemas ---

class ChakshuReportRequest(BaseModel):
    report_type: str        # e.g., "URL", "APK", "CALL_SPOOF", "SIM_SWAP"
    content: str            # e.g., the malicious URL or app package
    risk_score: float
    reported_at: str        # timestamp
    dossier_data: Optional[dict] = None  # gathered evidence (IP, SSL hash, HTML hash, etc.)

class ChakshuReportResponse(BaseModel):
    success: bool
    reference_id: str       # simulated government reference ID
    message: str
    timestamp: datetime


class VpnThreatEvent(BaseModel):
    domain_name: str
    verdict: str
    risk_score: float
    source: Optional[str] = "com.bankguard.app"


class PolyglotScanRequest(BaseModel):
    file_name: str
    detected_mime: str
    declared_mime: str
    is_polyglot: bool
    risk_score: float
    source: Optional[str] = "com.bankguard.app"


class MessageAnalysisRequest(BaseModel):
    text: str
    sender: str
    preferred_language: Optional[str] = "en"


class MessageDetectorScore(BaseModel):
    detector: str
    score: float
    label: Optional[str] = None


class MessageIndicator(BaseModel):
    name: str
    detected: bool = True
    evidence: Optional[str] = None


class MessageAnalysisResponse(BaseModel):
    tactic: str
    severity_score: float
    explanation: str
    suggested_action: str
    phishing_confidence: Optional[float] = None
    fused_confidence: Optional[float] = None
    detector_scores: list[MessageDetectorScore] = []
    indicators: list[MessageIndicator] = []
    model_version: Optional[str] = None


class UserDeviceProfileResponse(BaseModel):
    id: int
    customer_id: str
    device_key_pub: str
    sim_hash_baseline: str
    last_seen_ip: Optional[str] = None
    last_active: datetime
    is_locked: bool
    shield_points: int
    redeemed_vouchers: str

    class Config:
        from_attributes = True


class QuizSubmission(BaseModel):
    scenario_id: int
    is_malicious_guess: bool
    customer_id: str


class RedemptionRequest(BaseModel):
    reward_id: str
    customer_id: str


class CallSessionToggle(BaseModel):
    customer_id: str
    calling_number: str
    is_active: bool
    agent_name: str = "SBI Agent"


class DossierRequest(BaseModel):
    campaign_name: str
    threat_category: str
    target_identifier: str
    affected_states: list[str] = []


class TriageDossierResponse(BaseModel):
    takedown_email: str
    regex_rule: str
    push_notification_draft: str
    chakshu_payload: str
