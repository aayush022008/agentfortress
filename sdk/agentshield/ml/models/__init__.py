"""
Pre-trained model stubs. Run the ModelTrainer to generate actual model files.
This module provides fallback models trained on synthetic data for demonstration.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_MODELS_DIR = Path(__file__).parent


def get_model_path(model_name: str) -> str:
    """Return the path to a model file if it exists, otherwise None."""
    p = _MODELS_DIR / model_name
    return str(p) if p.exists() else ""


def load_default_nlp_classifier():
    """Load or create a default NLP classifier trained on synthetic data."""
    from ..nlp_classifier import NLPClassifier

    model_path = _MODELS_DIR / "nlp_classifier.pkl"
    if model_path.exists():
        return NLPClassifier.load(str(model_path))

    # Train on synthetic data
    clf = NLPClassifier()
    from .._synthetic_data import SYNTHETIC_PROMPTS
    texts = [p[0] for p in SYNTHETIC_PROMPTS]
    labels = [p[1] for p in SYNTHETIC_PROMPTS]
    clf.fit(texts, labels)
    clf.save(str(model_path))
    return clf


def load_default_isolation_forest():
    """Load or create a default Isolation Forest trained on synthetic data."""
    from ..isolation_forest import IsolationForestDetector

    model_path = _MODELS_DIR / "isolation_forest.pkl"
    if model_path.exists():
        return IsolationForestDetector.load(str(model_path))

    from .._synthetic_data import SYNTHETIC_SESSIONS
    detector = IsolationForestDetector()
    detector.fit(SYNTHETIC_SESSIONS)
    detector.save(str(model_path))
    return detector
