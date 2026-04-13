"""
Isolation Forest anomaly detection on agent telemetry vectors.
"""
from __future__ import annotations

import json
import os
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class IsolationForestDetector:
    """
    Anomaly detector using scikit-learn's Isolation Forest.

    Converts agent session telemetry into feature vectors and scores them.

    Usage::

        detector = IsolationForestDetector()
        # Train
        detector.fit(training_sessions)
        # Score
        score = detector.score_session(new_session)
        if score > 0.7:
            alert("Anomaly detected!")

        # Persist
        detector.save("model.pkl")
        detector2 = IsolationForestDetector.load("model.pkl")
    """

    FEATURE_NAMES = [
        "event_count",
        "tool_call_count",
        "unique_tools",
        "error_count",
        "error_rate",
        "session_duration",
        "avg_event_interval",
        "max_output_size",
        "external_calls",
        "file_ops",
    ]

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        self._scaler = StandardScaler()
        self._fitted = False

    def fit(self, sessions: List[Dict[str, Any]]) -> "IsolationForestDetector":
        """Train the model on a list of session dicts."""
        X = np.array([self._featurize(s) for s in sessions])
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._fitted = True
        return self

    def score_session(self, session: Dict[str, Any]) -> float:
        """
        Score a single session.
        Returns anomaly score 0.0 (normal) – 1.0 (anomalous).
        """
        if not self._fitted:
            raise RuntimeError("Model not fitted. Call fit() first.")
        vec = np.array(self._featurize(session)).reshape(1, -1)
        vec_scaled = self._scaler.transform(vec)
        # IsolationForest: -1 = anomaly, 1 = normal; score_samples returns negative anomaly score
        raw = self._model.score_samples(vec_scaled)[0]
        # Normalize: raw is typically in range [-0.5, 0]; map to [0, 1]
        normalized = max(0.0, min(1.0, -raw * 2))
        return round(float(normalized), 4)

    def predict(self, sessions: List[Dict[str, Any]]) -> List[int]:
        """Return -1 for anomaly, 1 for normal for each session."""
        if not self._fitted:
            raise RuntimeError("Model not fitted.")
        X = np.array([self._featurize(s) for s in sessions])
        X_scaled = self._scaler.transform(X)
        return self._model.predict(X_scaled).tolist()

    def save(self, path: str) -> None:
        """Persist model to disk."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"model": self._model, "scaler": self._scaler, "fitted": self._fitted}, f)

    @classmethod
    def load(cls, path: str) -> "IsolationForestDetector":
        """Load model from disk."""
        with open(path, "rb") as f:
            state = pickle.load(f)
        inst = cls()
        inst._model = state["model"]
        inst._scaler = state["scaler"]
        inst._fitted = state["fitted"]
        return inst

    # ------------------------------------------------------------------

    def _featurize(self, session: Dict[str, Any]) -> List[float]:
        events = session.get("events", [])
        tool_calls = [e for e in events if e.get("event_type") == "tool_call"]
        errors = [e for e in events if e.get("event_type") == "error"]
        tools_used = {e.get("tool_name", "") for e in tool_calls}
        external = [e for e in tool_calls if "http" in str(e.get("tool_name", "")).lower() or "request" in str(e.get("tool_name", "")).lower()]
        file_ops = [e for e in tool_calls if any(w in str(e.get("tool_name", "")).lower() for w in ["file", "read", "write", "open"])]

        duration = float(session.get("duration_seconds", 0.0))

        timestamps = []
        for e in events:
            ts = e.get("timestamp")
            if ts is not None:
                try:
                    timestamps.append(float(ts))
                except (TypeError, ValueError):
                    pass
        timestamps.sort()
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = sum(intervals) / len(intervals)
        else:
            avg_interval = 0.0

        output_sizes = []
        for e in events:
            output = e.get("output") or e.get("result") or ""
            output_sizes.append(len(str(output)))
        max_output = float(max(output_sizes)) if output_sizes else 0.0

        return [
            float(len(events)),
            float(len(tool_calls)),
            float(len(tools_used)),
            float(len(errors)),
            len(errors) / max(len(events), 1),
            duration,
            avg_interval,
            max_output,
            float(len(external)),
            float(len(file_ops)),
        ]
