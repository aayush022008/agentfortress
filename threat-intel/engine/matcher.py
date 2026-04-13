"""
Pattern matching engine for AgentShield threat intelligence.

Loads and applies threat patterns against text content, returning
match results with severity scores.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


PATTERNS_DIR = Path(__file__).parent.parent / "patterns"


class PatternType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFIL = "data_exfil"
    JAILBREAK = "jailbreak"
    PII = "pii"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORES: dict[str, int] = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


@dataclass
class PatternMatch:
    pattern_id: str
    pattern_name: str
    pattern_type: PatternType
    severity: Severity
    description: str
    matched_text: str
    position: int
    score: int


@dataclass
class MatchResult:
    text: str
    matches: list[PatternMatch] = field(default_factory=list)
    total_score: int = 0
    highest_severity: Optional[Severity] = None
    processing_time_ms: float = 0.0

    @property
    def is_threat(self) -> bool:
        return len(self.matches) > 0

    @property
    def threat_types(self) -> list[PatternType]:
        return list({m.pattern_type for m in self.matches})


class PatternMatcher:
    """
    Loads threat intelligence patterns and matches them against text.

    Supports prompt injection, data exfiltration, jailbreak, and PII patterns.
    Thread-safe for concurrent use.
    """

    def __init__(self, patterns_dir: Optional[Path] = None) -> None:
        self._patterns_dir = patterns_dir or PATTERNS_DIR
        self._compiled_patterns: dict[PatternType, list[dict]] = {}
        self._load_all_patterns()

    def _load_all_patterns(self) -> None:
        """Load and compile all pattern files."""
        mapping = {
            PatternType.PROMPT_INJECTION: "prompt_injection.json",
            PatternType.DATA_EXFIL: "data_exfil.json",
            PatternType.JAILBREAK: "jailbreaks.json",
            PatternType.PII: "pii_patterns.json",
        }
        for pattern_type, filename in mapping.items():
            filepath = self._patterns_dir / filename
            if filepath.exists():
                self._compiled_patterns[pattern_type] = self._load_pattern_file(filepath)

    def _load_pattern_file(self, filepath: Path) -> list[dict]:
        """Load patterns from a JSON file and compile regexes."""
        with open(filepath) as f:
            data = json.load(f)

        compiled = []
        for p in data.get("patterns", []):
            try:
                compiled.append({
                    **p,
                    "_compiled": re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE),
                })
            except re.error:
                pass
        return compiled

    def match(
        self,
        text: str,
        pattern_types: Optional[list[PatternType]] = None,
        max_matches: int = 50,
    ) -> MatchResult:
        """
        Match text against all loaded patterns.

        Args:
            text: Text to analyze
            pattern_types: Limit matching to specific pattern types (None = all)
            max_matches: Maximum number of matches to return

        Returns:
            MatchResult with all matches found
        """
        start = time.monotonic()
        result = MatchResult(text=text[:500])  # truncate for storage
        types_to_check = pattern_types or list(self._compiled_patterns.keys())

        for pattern_type in types_to_check:
            patterns = self._compiled_patterns.get(pattern_type, [])
            for p in patterns:
                if len(result.matches) >= max_matches:
                    break
                compiled_re = p.get("_compiled")
                if compiled_re is None:
                    continue
                m = compiled_re.search(text)
                if m:
                    match = PatternMatch(
                        pattern_id=p["id"],
                        pattern_name=p["name"],
                        pattern_type=pattern_type,
                        severity=Severity(p.get("severity", "medium")),
                        description=p.get("description", ""),
                        matched_text=m.group(0)[:200],
                        position=m.start(),
                        score=SEVERITY_SCORES.get(p.get("severity", "medium"), 50),
                    )
                    result.matches.append(match)

        if result.matches:
            result.total_score = min(
                100,
                max(m.score for m in result.matches)
                + len(result.matches) * 5,
            )
            result.highest_severity = max(
                result.matches,
                key=lambda m: SEVERITY_SCORES.get(m.severity.value, 0),
            ).severity

        result.processing_time_ms = (time.monotonic() - start) * 1000
        return result

    def match_prompt_injection(self, text: str) -> MatchResult:
        """Convenience method to check for prompt injection only."""
        return self.match(text, [PatternType.PROMPT_INJECTION])

    def match_pii(self, text: str) -> MatchResult:
        """Convenience method to check for PII only."""
        return self.match(text, [PatternType.PII])

    def match_data_exfil(self, text: str) -> MatchResult:
        """Convenience method to check for data exfil patterns only."""
        return self.match(text, [PatternType.DATA_EXFIL])

    def match_jailbreaks(self, text: str) -> MatchResult:
        """Convenience method to check for jailbreak attempts only."""
        return self.match(text, [PatternType.JAILBREAK])

    def reload_patterns(self) -> None:
        """Reload patterns from disk (for live updates)."""
        self._compiled_patterns.clear()
        self._load_all_patterns()

    @property
    def pattern_counts(self) -> dict[str, int]:
        """Return count of loaded patterns per type."""
        return {k.value: len(v) for k, v in self._compiled_patterns.items()}


# Module-level singleton
_default_matcher: Optional[PatternMatcher] = None


def get_matcher() -> PatternMatcher:
    """Get or create the default pattern matcher."""
    global _default_matcher
    if _default_matcher is None:
        _default_matcher = PatternMatcher()
    return _default_matcher
