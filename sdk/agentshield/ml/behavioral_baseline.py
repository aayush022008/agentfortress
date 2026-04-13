"""
Behavioral baseline profiler for agents.
Builds statistical profiles from telemetry and detects deviations.
"""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BaselineProfile:
    """Statistical profile for a single agent."""

    agent_id: str
    sample_count: int = 0
    feature_stats: Dict[str, Dict[str, float]] = field(default_factory=dict)
    """feature_name -> {mean, std, min, max, count}"""

    tool_call_freq: Dict[str, float] = field(default_factory=dict)
    """tool_name -> calls per session (mean)"""

    avg_session_duration: float = 0.0
    avg_events_per_session: float = 0.0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "sample_count": self.sample_count,
            "feature_stats": self.feature_stats,
            "tool_call_freq": self.tool_call_freq,
            "avg_session_duration": self.avg_session_duration,
            "avg_events_per_session": self.avg_events_per_session,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "BaselineProfile":
        p = cls(agent_id=d["agent_id"])
        p.sample_count = d["sample_count"]
        p.feature_stats = d["feature_stats"]
        p.tool_call_freq = d["tool_call_freq"]
        p.avg_session_duration = d.get("avg_session_duration", 0.0)
        p.avg_events_per_session = d.get("avg_events_per_session", 0.0)
        return p


class BehavioralBaseline:
    """
    Builds and maintains behavioral baseline profiles for agents.
    Flags sessions that deviate significantly from the baseline.

    Features extracted from session telemetry:
    - Tool call counts per tool
    - Session duration
    - Event count
    - Unique tools used
    - Error rate
    - Average response size

    Usage::

        baseline = BehavioralBaseline()
        # Train on historical sessions
        for session in historical_sessions:
            baseline.update("agent-001", session)

        # Score new session
        score, flags = baseline.score("agent-001", new_session)
        if score > 0.8:
            alert("Anomalous behavior detected!")
    """

    DEFAULT_SIGMA_THRESHOLD = 3.0  # flag if > 3 standard deviations

    def __init__(
        self,
        sigma_threshold: float = DEFAULT_SIGMA_THRESHOLD,
        min_samples: int = 10,
        profile_path: Optional[str] = None,
    ) -> None:
        self.sigma_threshold = sigma_threshold
        self.min_samples = min_samples
        self._profiles: Dict[str, BaselineProfile] = {}
        self._raw_data: Dict[str, List[Dict[str, float]]] = defaultdict(list)
        self._profile_path = profile_path

        if profile_path and Path(profile_path).exists():
            self._load_profiles()

    def update(self, agent_id: str, session: Dict[str, Any]) -> None:
        """Update the baseline with a new session observation."""
        features = self._extract_features(session)
        self._raw_data[agent_id].append(features)
        self._recompute_profile(agent_id)

        if self._profile_path:
            self._save_profiles()

    def score(
        self, agent_id: str, session: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Score a session against the agent's baseline.
        Returns (anomaly_score 0-1, list_of_flagged_features).
        0 = normal, 1 = maximally anomalous.
        Returns (0.0, []) if not enough baseline data.
        """
        if agent_id not in self._profiles:
            return 0.0, []

        profile = self._profiles[agent_id]
        if profile.sample_count < self.min_samples:
            return 0.0, []

        features = self._extract_features(session)
        flags: List[str] = []
        deviations: List[float] = []

        for feat_name, value in features.items():
            stats = profile.feature_stats.get(feat_name)
            if not stats or stats["std"] == 0:
                continue
            z_score = abs(value - stats["mean"]) / stats["std"]
            if z_score > self.sigma_threshold:
                flags.append(f"{feat_name}:z={z_score:.1f}")
            deviations.append(min(z_score / (self.sigma_threshold * 2), 1.0))

        anomaly_score = sum(deviations) / len(deviations) if deviations else 0.0
        return round(min(anomaly_score, 1.0), 4), flags

    def get_profile(self, agent_id: str) -> Optional[BaselineProfile]:
        return self._profiles.get(agent_id)

    def list_profiles(self) -> List[str]:
        return list(self._profiles.keys())

    # ------------------------------------------------------------------

    def _extract_features(self, session: Dict[str, Any]) -> Dict[str, float]:
        events = session.get("events", [])
        tool_calls = [e for e in events if e.get("event_type") == "tool_call"]
        errors = [e for e in events if e.get("event_type") == "error"]
        tools_used = {e.get("tool_name", "") for e in tool_calls}

        duration = session.get("duration_seconds", 0.0)
        if not duration and events:
            try:
                duration = (
                    float(events[-1].get("timestamp", 0)) - float(events[0].get("timestamp", 0))
                )
            except (TypeError, ValueError):
                duration = 0.0

        features: Dict[str, float] = {
            "event_count": float(len(events)),
            "tool_call_count": float(len(tool_calls)),
            "unique_tools": float(len(tools_used)),
            "error_count": float(len(errors)),
            "error_rate": len(errors) / max(len(events), 1),
            "session_duration": float(duration),
        }

        # Per-tool frequencies
        tool_counts: Dict[str, int] = defaultdict(int)
        for e in tool_calls:
            tool_counts[e.get("tool_name", "unknown")] += 1
        for tool, count in tool_counts.items():
            features[f"tool:{tool}"] = float(count)

        return features

    def _recompute_profile(self, agent_id: str) -> None:
        samples = self._raw_data[agent_id]
        if not samples:
            return

        # Gather all feature names
        all_features: set = set()
        for s in samples:
            all_features.update(s.keys())

        stats: Dict[str, Dict[str, float]] = {}
        for feat in all_features:
            vals = [s[feat] for s in samples if feat in s]
            if not vals:
                continue
            mean = sum(vals) / len(vals)
            variance = sum((v - mean) ** 2 for v in vals) / max(len(vals) - 1, 1)
            stats[feat] = {
                "mean": mean,
                "std": math.sqrt(variance),
                "min": min(vals),
                "max": max(vals),
                "count": float(len(vals)),
            }

        profile = self._profiles.setdefault(
            agent_id, BaselineProfile(agent_id=agent_id)
        )
        profile.sample_count = len(samples)
        profile.feature_stats = stats
        profile.updated_at = time.time()

    def _save_profiles(self) -> None:
        data = {aid: p.to_dict() for aid, p in self._profiles.items()}
        Path(self._profile_path).write_text(json.dumps(data, indent=2))  # type: ignore[arg-type]

    def _load_profiles(self) -> None:
        data = json.loads(Path(self._profile_path).read_text())  # type: ignore[arg-type]
        self._profiles = {aid: BaselineProfile.from_dict(d) for aid, d in data.items()}
