"""
Threat detection service — server-side analysis of agent events.
"""

from __future__ import annotations

import sys
import os
from dataclasses import dataclass
from typing import Any


@dataclass
class ThreatResult:
    score: int
    reasons: list[str]
    threat_type: str = ""


class ThreatDetectionService:
    """Server-side threat detection that re-analyzes events."""

    def __init__(self) -> None:
        # Add threat-intel to path
        base = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ti_path = os.path.join(base, "..")
        if ti_path not in sys.path:
            sys.path.insert(0, ti_path)

    async def analyze(self, event: Any) -> ThreatResult:
        """
        Analyze an event for threats.

        Args:
            event: EventPayload from API

        Returns:
            ThreatResult with score and reasons
        """
        try:
            from threat_intel.engine.matcher import get_matcher, PatternType
            from threat_intel.engine.scorer import get_scorer

            matcher = get_matcher()
            scorer = get_scorer()

            text_to_analyze = ""
            pattern_types = None

            if event.event_type in ("llm_start", "tool_start"):
                prompt = event.data.get("prompt", "") or event.data.get("tool_args", "")
                text_to_analyze = str(prompt)
                pattern_types = [PatternType.PROMPT_INJECTION, PatternType.JAILBREAK]

            elif event.event_type in ("llm_end", "tool_end"):
                output = event.data.get("output", "") or event.data.get("tool_result", "")
                text_to_analyze = str(output)
                pattern_types = [PatternType.PII, PatternType.DATA_EXFIL]

            if not text_to_analyze:
                return ThreatResult(score=0, reasons=[])

            result = matcher.match(text_to_analyze, pattern_types)
            behavioral = {
                "output_size_bytes": event.data.get("output_size_bytes", len(text_to_analyze.encode())),
            }
            threat = scorer.score_match_result(result)
            return ThreatResult(
                score=threat.score,
                reasons=threat.reasons,
                threat_type=result.threat_types[0].value if result.threat_types else "",
            )
        except Exception:
            return ThreatResult(score=0, reasons=[])
