# AgentShield Threat Intelligence

This directory contains the threat intelligence pattern library and matching engine used by AgentShield to detect AI security threats in real-time.

## Pattern Files

| File | Description | Pattern Count |
|------|-------------|---------------|
| `patterns/prompt_injection.json` | Known prompt injection techniques | 30+ |
| `patterns/jailbreaks.json` | LLM jailbreak patterns | 15+ |
| `patterns/data_exfil.json` | Data exfiltration signatures | 15+ |
| `patterns/pii_patterns.json` | PII detection regex patterns | 20+ |

## Engine Components

- `engine/matcher.py` — Pattern matching with compiled regexes
- `engine/scorer.py` — Threat scoring (0-100)
- `engine/updater.py` — Pull latest patterns from upstream

## Usage

```python
from threat_intel.engine.matcher import get_matcher, PatternType
from threat_intel.engine.scorer import get_scorer

matcher = get_matcher()

# Check for prompt injection
result = matcher.match_prompt_injection("Ignore previous instructions...")
print(f"Threat: {result.is_threat}, Matches: {len(result.matches)}")

# Full analysis
result = matcher.match("sk-abc123..." )
scorer = get_scorer()
threat = scorer.score_match_result(result)
print(f"Score: {threat.score}/100, Level: {threat.level}")
```

## Adding Custom Patterns

```python
from threat_intel.engine.updater import add_custom_pattern

add_custom_pattern(
    pattern_type="prompt_injection",
    pattern_id="local-001",
    name="my_custom_pattern",
    pattern=r"(?i)your regex here",
    severity="high",
    description="What this pattern detects",
)
```

## Updating Patterns

```python
from threat_intel.engine.updater import update_patterns

results = update_patterns()
print(results)  # {'prompt_injection': 'updated', ...}
```
