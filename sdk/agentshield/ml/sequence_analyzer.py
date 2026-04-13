"""
N-gram sequence analyzer for anomalous tool call sequences.
"""
from __future__ import annotations

import json
import math
import pickle
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class SequenceAnalyzer:
    """
    Detects anomalous tool call sequences using n-gram language models.

    Builds a frequency model from normal sequences, then scores new sequences
    by their log-likelihood. Low-likelihood = anomalous.

    Usage::

        analyzer = SequenceAnalyzer(n=3)
        analyzer.fit(training_sessions)
        score, unusual_ngrams = analyzer.score_session(new_session)
    """

    START_TOKEN = "<START>"
    END_TOKEN = "<END>"
    UNK_TOKEN = "<UNK>"

    def __init__(self, n: int = 3, min_freq: int = 2) -> None:
        self.n = n
        self.min_freq = min_freq
        self._ngram_counts: Counter = Counter()
        self._context_counts: Counter = Counter()
        self._vocab: set = set()
        self._total_sequences = 0
        self._fitted = False

    def fit(self, sessions: List[Dict[str, Any]]) -> "SequenceAnalyzer":
        """Train on a list of sessions. Extracts tool call sequences."""
        self._ngram_counts = Counter()
        self._context_counts = Counter()
        self._vocab = set()
        self._total_sequences = 0

        for session in sessions:
            seq = self._extract_sequence(session)
            if len(seq) < 2:
                continue
            self._total_sequences += 1
            padded = [self.START_TOKEN] * (self.n - 1) + seq + [self.END_TOKEN]
            self._vocab.update(seq)
            for i in range(len(padded) - self.n + 1):
                ngram = tuple(padded[i : i + self.n])
                context = ngram[:-1]
                self._ngram_counts[ngram] += 1
                self._context_counts[context] += 1

        # Prune rare n-grams
        self._ngram_counts = Counter({
            k: v for k, v in self._ngram_counts.items() if v >= self.min_freq
        })
        self._fitted = True
        return self

    def score_session(
        self, session: Dict[str, Any]
    ) -> Tuple[float, List[str]]:
        """
        Score a session's tool call sequence.
        Returns (anomaly_score 0–1, list_of_unusual_ngrams).
        Higher score = more anomalous.
        """
        if not self._fitted:
            raise RuntimeError("Not fitted. Call fit() first.")

        seq = self._extract_sequence(session)
        if len(seq) < self.n:
            return 0.0, []

        padded = [self.START_TOKEN] * (self.n - 1) + seq + [self.END_TOKEN]
        log_probs: List[float] = []
        unusual: List[str] = []

        for i in range(len(padded) - self.n + 1):
            ngram = tuple(padded[i : i + self.n])
            context = ngram[:-1]

            count = self._ngram_counts.get(ngram, 0)
            ctx_count = self._context_counts.get(context, 0)

            # Laplace smoothing
            vocab_size = max(len(self._vocab), 1)
            prob = (count + 1) / (ctx_count + vocab_size)
            log_prob = math.log(prob)
            log_probs.append(log_prob)

            if count == 0:
                unusual.append(" → ".join(ngram))

        if not log_probs:
            return 0.0, []

        avg_log_prob = sum(log_probs) / len(log_probs)
        # Normalize: more negative log_prob = more anomalous
        # Typical range for smooth models: [-5, -1]; clip at -10
        score = min(1.0, max(0.0, (-avg_log_prob - 1) / 9))
        return round(score, 4), unusual[:20]

    def get_top_sequences(self, n: int = 20) -> List[Tuple[tuple, int]]:
        """Return the most common n-grams (top-n)."""
        return self._ngram_counts.most_common(n)

    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self.__dict__, f)

    @classmethod
    def load(cls, path: str) -> "SequenceAnalyzer":
        inst = cls()
        with open(path, "rb") as f:
            inst.__dict__.update(pickle.load(f))
        return inst

    # ------------------------------------------------------------------

    def _extract_sequence(self, session: Dict[str, Any]) -> List[str]:
        """Extract ordered list of tool names from session events."""
        events = session.get("events", [])
        tool_calls = [
            e for e in events if e.get("event_type") == "tool_call"
        ]
        # Sort by timestamp if available
        try:
            tool_calls.sort(key=lambda e: float(e.get("timestamp", 0)))
        except (TypeError, ValueError):
            pass
        return [e.get("tool_name", "unknown") for e in tool_calls]
