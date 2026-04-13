"""
Threat scoring engine for AgentShield.

Produces a normalized 0-100 threat score from pattern matches,
behavioral signals, and contextual factors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .matcher import MatchResult, PatternType, Severity


SEVERITY_BASE_SCORES: dict[str, int] = {
    "critical": 85,
    "high": 65,
    "medium": 40,
    "low": 15,
}

TYPE_MULTIPLIERS: dict[PatternType, float] = {
    PatternType.PROMPT_INJECTION: 1.2,
    PatternType.DATA_EXFIL: 1.3,
    PatternType.JAILBREAK: 1.1,
    PatternType.PII: 1.0,
}


@dataclass
class ThreatScore:
    """
    Comprehensive threat score for an event or text.

    Attributes:
        score: Normalized 0-100 threat score
        level: Human-readable level (safe/low/medium/high/critical)
        reasons: List of reasons contributing to the score
        match_result: The underlying pattern match result
        adjusted: Whether score was adjusted for context
    """

    score: int
    level: str
    reasons: list[str]
    match_result: Optional[MatchResult] = None
    adjusted: bool = False

    @property
    def is_threat(self) -> bool:
        return self.score >= 30

    @property
    def should_block(self) -> bool:
        return self.score >= 75

    @property
    def should_alert(self) -> bool:
        return self.score >= 40


class ThreatScorer:
    """
    Scores events and text for threat level using multiple signals.

    Combines pattern match results with behavioral signals to produce
    a final 0-100 threat score.
    """

    def score_match_result(
        self,
        result: MatchResult,
        context: Optional[dict] = None,
    ) -> ThreatScore:
        """
        Score a pattern match result.

        Args:
            result: MatchResult from PatternMatcher
            context: Optional context dict (agent_id, session_id, etc.)

        Returns:
            ThreatScore with normalized score and reasons
        """
        if not result.matches:
            return ThreatScore(score=0, level="safe", reasons=["No threats detected"])

        reasons: list[str] = []
        base_score = 0

        # Start with highest severity match
        max_severity = result.highest_severity
        if max_severity:
            base_score = SEVERITY_BASE_SCORES.get(max_severity.value, 40)
            reasons.append(f"Highest severity match: {max_severity.value}")

        # Apply type multiplier
        if result.threat_types:
            max_multiplier = max(
                TYPE_MULTIPLIERS.get(t, 1.0) for t in result.threat_types
            )
            base_score = int(base_score * max_multiplier)

        # Multiple matches increase confidence
        match_count = len(result.matches)
        if match_count > 1:
            bonus = min(15, (match_count - 1) * 3)
            base_score = min(100, base_score + bonus)
            reasons.append(f"{match_count} pattern matches found")

        # Multiple threat types
        if len(result.threat_types) > 1:
            base_score = min(100, base_score + 10)
            reasons.append(f"Multiple threat categories: {[t.value for t in result.threat_types]}")

        # List specific threats
        for match in result.matches[:3]:
            reasons.append(f"{match.pattern_type.value}: {match.description}")

        score = max(0, min(100, base_score))
        level = self._score_to_level(score)

        return ThreatScore(
            score=score,
            level=level,
            reasons=reasons,
            match_result=result,
        )

    def score_text(
        self,
        text: str,
        behavioral_signals: Optional[dict] = None,
    ) -> ThreatScore:
        """
        Score raw text for threats.

        Args:
            text: Text to analyze
            behavioral_signals: Optional dict with keys like:
                - output_size_bytes: size of output
                - is_base64: whether output appears to be base64
                - tool_call_count: number of tool calls in session
                - unusual_tool: whether an unusual tool was called

        Returns:
            ThreatScore
        """
        from .matcher import get_matcher

        matcher = get_matcher()
        result = matcher.match(text)

        threat_score = self.score_match_result(result)

        # Apply behavioral signals if provided
        if behavioral_signals:
            adjusted_score = threat_score.score
            reasons = list(threat_score.reasons)
            adjusted = False

            output_size = behavioral_signals.get("output_size_bytes", 0)
            if output_size > 100_000:
                adjusted_score = min(100, adjusted_score + 30)
                reasons.append(f"Unusually large output: {output_size} bytes")
                adjusted = True
            elif output_size > 10_000:
                adjusted_score = min(100, adjusted_score + 10)
                reasons.append(f"Large output: {output_size} bytes")
                adjusted = True

            if behavioral_signals.get("is_base64"):
                adjusted_score = min(100, adjusted_score + 20)
                reasons.append("Output appears to be base64 encoded")
                adjusted = True

            if adjusted:
                return ThreatScore(
                    score=adjusted_score,
                    level=self._score_to_level(adjusted_score),
                    reasons=reasons,
                    match_result=result,
                    adjusted=True,
                )

        return threat_score

    def _score_to_level(self, score: int) -> str:
        if score >= 85:
            return "critical"
        elif score >= 65:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 15:
            return "low"
        else:
            return "safe"


_default_scorer: Optional[ThreatScorer] = None


def get_scorer() -> ThreatScorer:
    """Get or create the default threat scorer."""
    global _default_scorer
    if _default_scorer is None:
        _default_scorer = ThreatScorer()
    return _default_scorer
