"""
Text Classifier - production inference wrapper for phishing-like message detection.

Loads once at backend startup and reuses the same model instance for all requests.
The primary model is ealvaradob/bert-finetuned-phishing.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class TextIndicator:
    name: str
    detected: bool
    evidence: Optional[str] = None


@dataclass
class TextClassificationResult:
    verdict: str
    confidence: float
    raw_probability: float
    model_version: str
    inference_time_ms: float = 0.0
    indicators: list[TextIndicator] = field(default_factory=list)
    phishing_confidence: float = 0.0
    backend_label: str = "UNKNOWN"
    is_phishing: bool = False


class TextClassifier:
    """Wrapper around the backend phishing text model."""

    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.model_id = os.getenv(
            "BANKGUARD_TEXT_MODEL_ID",
            "ealvaradob/bert-finetuned-phishing",
        )
        self.threshold = 0.5
        self.is_loaded = False
        self.api_url = f"https://router.huggingface.co/hf-inference/models/{self.model_id}"
        self.hf_token = os.getenv("HF_TOKEN")
        self._load_model()

    def _load_model(self) -> None:
        # The Hugging Face Serverless API is configured
        self.is_loaded = True
        logger.info("Configured Hugging Face API client for model: %s", self.model_id)

    def predict(self, text: str) -> Optional[TextClassificationResult]:
        if not text:
            return None

        start = time.time()
        indicators = self._extract_indicators(text)
        raw_probability = 0.0
        backend_label = "UNKNOWN"

        if self.is_loaded:
            try:
                import requests
                headers = {}
                if self.hf_token:
                    headers["Authorization"] = f"Bearer {self.hf_token}"

                resp = requests.post(
                    self.api_url,
                    headers=headers,
                    json={"inputs": text[:4000]},
                    timeout=10,
                )
                if resp.status_code == 200:
                    output = resp.json()
                    # Safe unpacking for various Hugging Face API formats
                    if isinstance(output, list) and len(output) > 0:
                        payload = output[0]
                        if isinstance(payload, list) and len(payload) > 0:
                            payload = payload[0]
                    else:
                        payload = output

                    if isinstance(payload, dict):
                        backend_label = str(payload.get("label", "UNKNOWN")).upper()
                        raw_probability = float(payload.get("score", 0.0))
                else:
                    logger.warning("Hugging Face API returned status code %d: %s", resp.status_code, resp.text)
            except Exception as exc:
                logger.warning("Hugging Face API inference failed: %s", exc)

        lexical_boost = self._indicator_boost(indicators)

        if backend_label in {"SPAM", "LABEL_1", "PHISHING", "MALICIOUS"}:
            phishing_prob = raw_probability
        elif backend_label in {"HAM", "LABEL_0", "SAFE", "BENIGN"}:
            phishing_prob = 1.0 - raw_probability
        else:
            phishing_prob = 0.0

        phishing_confidence = max(phishing_prob, lexical_boost)
        phishing_confidence = min(max(phishing_confidence, 0.0), 1.0)
        verdict = "MALICIOUS" if phishing_confidence >= 0.85 else (
            "SUSPICIOUS" if phishing_confidence >= self.threshold else "SAFE"
        )

        inference_ms = (time.time() - start) * 1000
        return TextClassificationResult(
            verdict=verdict,
            confidence=round(phishing_confidence * 100, 2),
            raw_probability=round(raw_probability, 4),
            model_version=self.model_id,
            inference_time_ms=round(inference_ms, 2),
            indicators=indicators,
            phishing_confidence=round(phishing_confidence, 4),
            backend_label=backend_label,
            is_phishing=phishing_confidence >= self.threshold,
        )

    def _extract_indicators(self, text: str) -> list[TextIndicator]:
        lower_text = text.lower()
        patterns = [
            ("banking_impersonation", ["sbi", "yono", "bank", "netbanking", "credit card", "debit card"], "banking vocabulary"),
            ("urgency_language", ["urgent", "immediately", "within 24 hours", "block", "expire", "last warning", "final notice"], "urgency cues"),
            ("reward_scam", ["reward", "gift", "prize", "cashback", "win", "winner", "redeem"], "reward bait"),
            ("kyc_scam", ["kyc", "pan", "update kyc", "verify kyc", "re-kyc"], "kyc wording"),
            ("government_impersonation", ["cbi", "police", "government", "income tax", "rbi", "court", "consumer court", "digital arrest"], "official impersonation"),
            ("credential_theft", ["otp", "password", "pin", "cvv", "credential", "login", "account details", "share your code"], "credential request"),
        ]

        indicators: list[TextIndicator] = []
        for name, keywords, evidence in patterns:
            hit = next((kw for kw in keywords if kw in lower_text), None)
            indicators.append(
                TextIndicator(
                    name=name,
                    detected=hit is not None,
                    evidence=hit or evidence,
                )
            )
        has_http_url = re.search(r"\bhttps?://\S+", text, flags=re.IGNORECASE) is not None
        domain_pattern = r"\b[a-z0-9\-]+?\s*\.\s*(?:com|in|net|xyz|online|org|info|click|work|app|cc|co)\b"
        has_bare_domain = re.search(domain_pattern, lower_text, flags=re.IGNORECASE) is not None
        if has_http_url or has_bare_domain:
            indicators.append(TextIndicator(name="contains_url", detected=True, evidence="url present"))

        return indicators

    def _indicator_boost(self, indicators: list[TextIndicator]) -> float:
        boost_weights = {
            "credential_theft": 0.28,
            "government_impersonation": 0.26,
            "kyc_scam": 0.24,
            "urgency_language": 0.18,
            "banking_impersonation": 0.20,
            "reward_scam": 0.14,
            "contains_url": 0.08,
        }
        score = 0.0
        for item in indicators:
            if item.detected:
                score += boost_weights.get(item.name, 0.05)
        return min(score, 0.95)
