"""
Backend ML Package - URL and message phishing classification.

Exposes singleton classifier instances loaded at import time.
Falls back gracefully if model files are missing.
"""

import os
import logging

logger = logging.getLogger(__name__)

ML_DIR = os.path.dirname(os.path.abspath(__file__))

# Try to initialize the classifiers at import time
_classifier = None
_text_classifier = None

try:
    from .url_classifier import URLClassifier
    _classifier = URLClassifier(model_dir=ML_DIR)
    logger.info("ML URL classifier loaded successfully")
except Exception as e:
    logger.warning(f"ML URL classifier not available: {e}")
    logger.warning("Falling back to heuristic-only mode")

try:
    from .text_classifier import TextClassifier
    _text_classifier = TextClassifier(model_dir=ML_DIR)
    logger.info("ML text classifier loaded successfully")
except Exception as e:
    logger.warning(f"ML text classifier not available: {e}")
    logger.warning("Falling back to heuristic-only message mode")


def get_classifier():
    """Get the loaded classifier, or None if unavailable."""
    return _classifier


def get_text_classifier():
    """Get the loaded text classifier, or None if unavailable."""
    return _text_classifier
