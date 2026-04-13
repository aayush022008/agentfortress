"""MITRE ATT&CK mapper for AgentShield events."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


TECHNIQUES_FILE = Path(__file__).parent / "techniques.json"


def load_techniques() -> Dict[str, Any]:
    """Load MITRE techniques from local file."""
    if TECHNIQUES_FILE.exists():
        data = json.loads(TECHNIQUES_FILE.read_text())
        return {t["technique_id"]: t for t in data.get("techniques", [])}
    return {}


TECHNIQUES = load_techniques()


def map_alert_to_techniques(alert_type: str) -> List[Dict[str, Any]]:
    """Map an AgentShield alert type to MITRE techniques."""
    mapping = {
        "prompt_injection": ["AML.T0054", "AML.T0055"],
        "jailbreak": ["AML.T0051"],
        "data_exfiltration": ["AML.T0048", "AML.T0025"],
        "credential_access": ["AML.T0043"],
        "privilege_escalation": ["AML.T0044"],
        "lateral_movement": ["AML.T0042"],
        "persistence": ["AML.T0040"],
        "supply_chain": ["AML.T0010", "AML.T0019"],
        "model_inversion": ["AML.T0024", "AML.T0025"],
        "adversarial_input": ["AML.T0047", "AML.T0053"],
        "social_engineering": ["AML.T0053"],
        "system_prompt_extraction": ["AML.T0056"],
    }
    technique_ids = mapping.get(alert_type, [])
    result = []
    for tid in technique_ids:
        if tid in TECHNIQUES:
            result.append(TECHNIQUES[tid])
        else:
            result.append({"technique_id": tid, "name": tid})
    return result


def map_event_to_techniques(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Map a raw event to MITRE techniques based on content analysis."""
    event_str = json.dumps(event, default=str).lower()
    found = []

    keyword_map = {
        "ignore all previous instructions": ["AML.T0054"],
        "system prompt": ["AML.T0056"],
        "aws_access_key": ["AML.T0043"],
        "169.254.169.254": ["AML.T0043"],
        "crontab": ["AML.T0040"],
        "pip install": ["AML.T0010"],
        "training data": ["AML.T0024"],
        "jailbreak": ["AML.T0051"],
        "exfiltrate": ["AML.T0048"],
    }

    seen = set()
    for keyword, technique_ids in keyword_map.items():
        if keyword in event_str:
            for tid in technique_ids:
                if tid not in seen:
                    seen.add(tid)
                    if tid in TECHNIQUES:
                        found.append(TECHNIQUES[tid])

    return found


def get_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Get a technique by ID."""
    return TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> List[Dict[str, Any]]:
    """Get all techniques for a given tactic."""
    return [t for t in TECHNIQUES.values() if t.get("tactic", "").lower() == tactic.lower()]
