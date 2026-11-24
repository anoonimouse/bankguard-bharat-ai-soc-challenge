from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class URLCheckRequest(BaseModel):
    url: str

class MLFeatureImportance(BaseModel):
    feature: str
    importance: float

class MLAnalysis(BaseModel):
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

class FraudReportResponse(FraudReportCreate):
    id: int
    status: str
    reported_at: datetime

    class Config:
        from_attributes = True # updated for Pydantic V2

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
