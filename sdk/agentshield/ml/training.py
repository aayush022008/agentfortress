"""
Model trainer — train/retrain all AgentShield ML models on collected data.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .behavioral_baseline import BehavioralBaseline
from .isolation_forest import IsolationForestDetector
from .nlp_classifier import NLPClassifier
from .sequence_analyzer import SequenceAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class TrainingResult:
    model_name: str
    success: bool
    samples_used: int
    duration_seconds: float
    metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class ModelTrainer:
    """
    Orchestrates training and retraining of all AgentShield ML models.

    Usage::

        trainer = ModelTrainer(model_dir="/var/agentshield/models")
        results = trainer.train_all(sessions=sessions, labeled_prompts=labeled)
        for r in results:
            print(r.model_name, "success" if r.success else r.error)
    """

    def __init__(self, model_dir: str = "models") -> None:
        self._dir = Path(model_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def train_isolation_forest(
        self, sessions: List[Dict[str, Any]], contamination: float = 0.1
    ) -> TrainingResult:
        """Train Isolation Forest anomaly detector."""
        start = time.time()
        try:
            detector = IsolationForestDetector(contamination=contamination)
            detector.fit(sessions)
            path = str(self._dir / "isolation_forest.pkl")
            detector.save(path)
            duration = time.time() - start
            logger.info("Isolation Forest trained: %d samples → %s", len(sessions), path)
            return TrainingResult(
                model_name="isolation_forest",
                success=True,
                samples_used=len(sessions),
                duration_seconds=duration,
                metrics={"contamination": contamination, "path": path},
            )
        except Exception as e:
            return TrainingResult(
                model_name="isolation_forest",
                success=False,
                samples_used=len(sessions),
                duration_seconds=time.time() - start,
                error=str(e),
            )

    def train_sequence_analyzer(
        self, sessions: List[Dict[str, Any]], n: int = 3
    ) -> TrainingResult:
        """Train n-gram sequence analyzer."""
        start = time.time()
        try:
            analyzer = SequenceAnalyzer(n=n)
            analyzer.fit(sessions)
            path = str(self._dir / "sequence_analyzer.pkl")
            analyzer.save(path)
            return TrainingResult(
                model_name="sequence_analyzer",
                success=True,
                samples_used=len(sessions),
                duration_seconds=time.time() - start,
                metrics={"n": n, "path": path},
            )
        except Exception as e:
            return TrainingResult(
                model_name="sequence_analyzer",
                success=False,
                samples_used=len(sessions),
                duration_seconds=time.time() - start,
                error=str(e),
            )

    def train_nlp_classifier(
        self, labeled_data: List[Tuple[str, int]]
    ) -> TrainingResult:
        """
        Train NLP classifier for prompt injection detection.
        labeled_data: list of (text, label) where label 0=normal, 1=malicious.
        """
        start = time.time()
        try:
            texts = [d[0] for d in labeled_data]
            labels = [d[1] for d in labeled_data]
            clf = NLPClassifier()
            clf.fit(texts, labels)
            path = str(self._dir / "nlp_classifier.pkl")
            clf.save(path)
            return TrainingResult(
                model_name="nlp_classifier",
                success=True,
                samples_used=len(labeled_data),
                duration_seconds=time.time() - start,
                metrics={"path": path},
            )
        except Exception as e:
            return TrainingResult(
                model_name="nlp_classifier",
                success=False,
                samples_used=len(labeled_data),
                duration_seconds=time.time() - start,
                error=str(e),
            )

    def train_behavioral_baselines(
        self, sessions_by_agent: Dict[str, List[Dict[str, Any]]]
    ) -> TrainingResult:
        """Train behavioral baselines for each agent."""
        start = time.time()
        try:
            path = str(self._dir / "behavioral_baselines.json")
            baseline = BehavioralBaseline(profile_path=path)
            total = 0
            for agent_id, sessions in sessions_by_agent.items():
                for session in sessions:
                    baseline.update(agent_id, session)
                    total += 1
            return TrainingResult(
                model_name="behavioral_baseline",
                success=True,
                samples_used=total,
                duration_seconds=time.time() - start,
                metrics={"agents": len(sessions_by_agent), "path": path},
            )
        except Exception as e:
            return TrainingResult(
                model_name="behavioral_baseline",
                success=False,
                samples_used=0,
                duration_seconds=time.time() - start,
                error=str(e),
            )

    def train_all(
        self,
        sessions: List[Dict[str, Any]],
        labeled_prompts: Optional[List[Tuple[str, int]]] = None,
        sessions_by_agent: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    ) -> List[TrainingResult]:
        """Train all models. Returns list of results."""
        results: List[TrainingResult] = []

        if sessions:
            results.append(self.train_isolation_forest(sessions))
            results.append(self.train_sequence_analyzer(sessions))

        if labeled_prompts:
            results.append(self.train_nlp_classifier(labeled_prompts))

        if sessions_by_agent:
            results.append(self.train_behavioral_baselines(sessions_by_agent))
        elif sessions:
            # Group sessions by agent_id if present
            by_agent: Dict[str, List[Dict[str, Any]]] = {}
            for s in sessions:
                aid = s.get("agent_id", "default")
                by_agent.setdefault(aid, []).append(s)
            results.append(self.train_behavioral_baselines(by_agent))

        # Save training manifest
        manifest = {
            "trained_at": time.time(),
            "results": [
                {
                    "model": r.model_name,
                    "success": r.success,
                    "samples": r.samples_used,
                    "duration": r.duration_seconds,
                }
                for r in results
            ],
        }
        (self._dir / "training_manifest.json").write_text(json.dumps(manifest, indent=2))
        return results

    def load_isolation_forest(self) -> IsolationForestDetector:
        return IsolationForestDetector.load(str(self._dir / "isolation_forest.pkl"))

    def load_sequence_analyzer(self) -> SequenceAnalyzer:
        return SequenceAnalyzer.load(str(self._dir / "sequence_analyzer.pkl"))

    def load_nlp_classifier(self) -> NLPClassifier:
        return NLPClassifier.load(str(self._dir / "nlp_classifier.pkl"))
