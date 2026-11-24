"""
URL Classifier - Production inference wrapper for the XGBoost phishing model.

Loaded once at backend startup, reused for all requests.
Inference must complete in under 100ms per URL.
"""

import os
import json
import time
import logging
import warnings
from typing import Optional
from dataclasses import dataclass, field

import joblib
import numpy as np

# Import feature engineering and whitelist from same directory
from .feature_engineering import extract_features, FEATURE_NAMES
from .whitelist import get_domain_trust_tier

# Suppress XGBoost serialization version mismatch warnings
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")

logger = logging.getLogger(__name__)


@dataclass
class FeatureImportance:
    """A single feature contributing to the classification decision."""
    feature: str
    importance: float


@dataclass
class URLClassificationResult:
    """Result from the ML classifier."""
    verdict: str              # SAFE, SUSPICIOUS, MALICIOUS
    confidence: int           # 0-100 (confidence percentage)
    raw_probability: float    # Raw model probability 0.0-1.0
    is_phishing: bool         # Whether URL crossed the threshold
    threshold_used: float     # The threshold that was applied
    top_features: list = field(default_factory=list)  # Top 5 features
    model_version: str = "1.0.0"
    inference_time_ms: float = 0.0
    is_whitelisted: bool = False
    trust_tier: int = 0  # 0=none, 1=.bank.in, 2=legacy banking, 3=general trusted


class URLClassifier:
    """
    Wraps the trained XGBoost phishing detection model
    for use in the FastAPI URL checking pipeline.

    Loaded once at startup, reused for all requests.
    Falls back to heuristics if model files are missing.
    """

    def __init__(self, model_dir: str):
        self.model_dir = model_dir
        self.model = None
        self.threshold = 0.5
        self.feature_names = FEATURE_NAMES
        self.metadata = {}
        self.is_loaded = False

        self._load_model()

    def _load_model(self):
        """Load model, threshold, and metadata from disk."""
        model_path = os.path.join(self.model_dir, "xgb_phishing_model.pkl")
        threshold_path = os.path.join(self.model_dir, "optimal_threshold.json")
        metadata_path = os.path.join(self.model_dir, "model_metadata.json")
        fn_path = os.path.join(self.model_dir, "feature_names.json")

        if not os.path.exists(model_path):
            logger.error(f"Model file not found at {model_path}")
            return

        start = time.time()
        self.model = joblib.load(model_path)
        load_time = time.time() - start

        if os.path.exists(threshold_path):
            with open(threshold_path, "r", encoding="utf-8") as f:
                self.threshold = json.load(f)["threshold"]

        if os.path.exists(fn_path):
            with open(fn_path, "r", encoding="utf-8") as f:
                self.feature_names = json.load(f)

        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

        self.is_loaded = True
        logger.info(f"ML model loaded in {load_time:.2f}s - "
                     f"version={self.metadata.get('model_version', '?')}, "
                     f"threshold={self.threshold}, "
                     f"features={len(self.feature_names)}")

        if load_time > 2.0:
            logger.warning(f"Model load time {load_time:.2f}s exceeds 2s target")

    def predict(self, url: str) -> Optional[URLClassificationResult]:
        """
        Classify a URL using the trained model.

        Returns URLClassificationResult or None if model isn't loaded.
        """
        if not self.is_loaded or self.model is None:
            return None

        start = time.time()

        # Check whitelist first -- instant bypass for trusted domains
        tier = get_domain_trust_tier(url)
        if tier > 0:
            inference_ms = (time.time() - start) * 1000
            return URLClassificationResult(
                verdict="SAFE",
                confidence=0,
                raw_probability=0.0,
                is_phishing=False,
                threshold_used=self.threshold,
                is_whitelisted=True,
                trust_tier=tier,
                model_version=self.metadata.get("model_version", "1.0.0"),
                inference_time_ms=round(inference_ms, 2),
            )

        # Extract features
        features = extract_features(url)
        feature_vec = np.array([[features.get(name, 0.0) for name in self.feature_names]])

        # Run inference
        raw_prob = float(self.model.predict_proba(feature_vec)[0, 1])

        is_phishing = raw_prob >= self.threshold
        confidence = int(raw_prob * 100)

        inference_ms = (time.time() - start) * 1000
        if inference_ms > 100:
            logger.warning(f"Inference took {inference_ms:.1f}ms (>100ms target) for {url}")

        # Determine verdict
        if raw_prob >= 0.9:
            verdict = "MALICIOUS"
        elif raw_prob >= self.threshold:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # Get feature importances for explainability
        top_features = self._get_top_features(features, n=5)

        return URLClassificationResult(
            verdict=verdict,
            confidence=confidence,
            raw_probability=round(raw_prob, 4),
            is_phishing=is_phishing,
            threshold_used=self.threshold,
            top_features=top_features,
            model_version=self.metadata.get("model_version", "1.0.0"),
            inference_time_ms=round(inference_ms, 2),
        )

    def _get_top_features(self, features: dict, n: int = 5) -> list:
        """
        Get the top N features that drove this classification.
        Uses the model's built-in feature importance scores,
        filtered to only show features that are non-zero for this URL.
        """
        importances = self.model.feature_importances_
        pairs = []
        for i, name in enumerate(self.feature_names):
            if i < len(importances) and features.get(name, 0) != 0:
                pairs.append(FeatureImportance(
                    feature=name,
                    importance=round(float(importances[i]), 4),
                ))

        pairs.sort(key=lambda x: x.importance, reverse=True)
        return pairs[:n]
