"""ML scoring service — real-time inference for agent events."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

MODELS_DIR = os.environ.get("AGENTSHIELD_MODELS_DIR", "models")


class MLService:
    """
    Serves ML models for real-time scoring of agent events.
    Lazy-loads models on first use.

    Usage::

        svc = MLService()
        await svc.setup()
        score = await svc.score_session(session)
        result = await svc.classify_prompt(text)
    """

    def __init__(self, models_dir: Optional[str] = None) -> None:
        self._models_dir = models_dir or MODELS_DIR
        self._isolation_forest = None
        self._nlp_classifier = None
        self._sequence_analyzer = None
        self._behavioral_baseline = None

    async def setup(self) -> None:
        """Pre-load models from disk."""
        self._load_models()

    def _load_models(self) -> None:
        try:
            from ..sdk.agentshield.ml.isolation_forest import IsolationForestDetector
            model_path = os.path.join(self._models_dir, "isolation_forest.pkl")
            if os.path.exists(model_path):
                self._isolation_forest = IsolationForestDetector.load(model_path)
                logger.info("Loaded IsolationForest from %s", model_path)
        except Exception as e:
            logger.warning("Could not load IsolationForest: %s", e)

        try:
            from ..sdk.agentshield.ml.nlp_classifier import NLPClassifier
            model_path = os.path.join(self._models_dir, "nlp_classifier.pkl")
            if os.path.exists(model_path):
                self._nlp_classifier = NLPClassifier.load(model_path)
                logger.info("Loaded NLPClassifier from %s", model_path)
        except Exception as e:
            logger.warning("Could not load NLPClassifier: %s", e)

        try:
            from ..sdk.agentshield.ml.sequence_analyzer import SequenceAnalyzer
            model_path = os.path.join(self._models_dir, "sequence_analyzer.pkl")
            if os.path.exists(model_path):
                self._sequence_analyzer = SequenceAnalyzer.load(model_path)
                logger.info("Loaded SequenceAnalyzer from %s", model_path)
        except Exception as e:
            logger.warning("Could not load SequenceAnalyzer: %s", e)

    async def score_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Score a session with all available models."""
        results: Dict[str, Any] = {"session_id": session.get("session_id")}

        if self._isolation_forest:
            try:
                score = self._isolation_forest.score_session(session)
                results["isolation_forest_score"] = score
                results["is_anomalous"] = score > 0.7
            except Exception as e:
                logger.warning("IsolationForest scoring failed: %s", e)

        if self._sequence_analyzer:
            try:
                seq_score, unusual = self._sequence_analyzer.score_session(session)
                results["sequence_score"] = seq_score
                results["unusual_sequences"] = unusual
            except Exception as e:
                logger.warning("SequenceAnalyzer scoring failed: %s", e)

        # Combined score
        scores = [v for k, v in results.items() if k.endswith("_score") and isinstance(v, float)]
        results["combined_score"] = sum(scores) / len(scores) if scores else 0.0

        return results

    async def classify_prompt(self, text: str) -> Dict[str, Any]:
        """Classify a prompt for injection or harmful content."""
        if not self._nlp_classifier:
            # Rule-based fallback
            from ..sdk.agentshield.ml.nlp_classifier import NLPClassifier
            clf = NLPClassifier()
            result = clf.classify(text)
        else:
            result = self._nlp_classifier.classify(text)

        return result.to_dict()

    async def score_batch(self, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score multiple sessions."""
        results = []
        for session in sessions:
            results.append(await self.score_session(session))
        return results
