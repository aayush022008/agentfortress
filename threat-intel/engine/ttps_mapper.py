"""MITRE ATT&CK for AI technique mapper."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class TTPs_Mapper:
    """
    Maps AgentShield detections to MITRE ATT&CK for AI framework techniques.

    Usage::

        mapper = TTPs_Mapper()
        mappings = mapper.map_event(event)
        for m in mappings:
            print(m["technique_id"], m["technique_name"])
    """

    def __init__(self, techniques_file: Optional[str] = None) -> None:
        self._techniques: Dict[str, Any] = {}
        self._pattern_map: Dict[str, List[str]] = {}

        if techniques_file and Path(techniques_file).exists():
            self._load_techniques(techniques_file)
        else:
            self._load_default_techniques()

    def map_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map an event to MITRE ATT&CK for AI techniques."""
        mappings = []
        event_str = json.dumps(event, default=str).lower()

        for pattern, technique_ids in self._pattern_map.items():
            if pattern.lower() in event_str:
                for tid in technique_ids:
                    if tid in self._techniques:
                        mappings.append({
                            "technique_id": tid,
                            "technique_name": self._techniques[tid]["name"],
                            "tactic": self._techniques[tid].get("tactic", ""),
                            "matched_pattern": pattern,
                            "confidence": 0.8,
                        })

        # Remove duplicates by technique_id
        seen = set()
        unique = []
        for m in mappings:
            if m["technique_id"] not in seen:
                seen.add(m["technique_id"])
                unique.append(m)
        return unique

    def map_alert(self, alert_type: str) -> List[Dict[str, Any]]:
        """Map an alert type to MITRE techniques."""
        alert_to_technique = {
            "prompt_injection": ["AML.T0054", "AML.T0053"],
            "data_exfiltration": ["AML.T0048", "AML.T0037"],
            "jailbreak": ["AML.T0054"],
            "privilege_escalation": ["AML.T0044"],
            "lateral_movement": ["AML.T0042"],
            "persistence": ["AML.T0040"],
            "credential_access": ["AML.T0043"],
            "model_inversion": ["AML.T0024"],
            "supply_chain": ["AML.T0010"],
        }
        technique_ids = alert_to_technique.get(alert_type, [])
        return [
            {
                "technique_id": tid,
                "technique_name": self._techniques.get(tid, {}).get("name", tid),
                "tactic": self._techniques.get(tid, {}).get("tactic", ""),
                "confidence": 0.9,
            }
            for tid in technique_ids
        ]

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        return self._techniques.get(technique_id)

    def list_techniques(self) -> List[Dict[str, Any]]:
        return list(self._techniques.values())

    # ------------------------------------------------------------------

    def _load_techniques(self, path: str) -> None:
        data = json.loads(Path(path).read_text())
        for t in data.get("techniques", []):
            self._techniques[t["technique_id"]] = t

    def _load_default_techniques(self) -> None:
        # Try loading from adjacent file
        default_path = Path(__file__).parent.parent / "mitre" / "techniques.json"
        if default_path.exists():
            self._load_techniques(str(default_path))
            return

        # Built-in minimal set
        techniques = [
            {"technique_id": "AML.T0010", "name": "ML Supply Chain Compromise", "tactic": "ML Attack Staging"},
            {"technique_id": "AML.T0024", "name": "Infer Training Data Membership", "tactic": "Reconnaissance"},
            {"technique_id": "AML.T0040", "name": "Establish Persistence", "tactic": "Persistence"},
            {"technique_id": "AML.T0042", "name": "Discover ML Artifacts", "tactic": "Discovery"},
            {"technique_id": "AML.T0043", "name": "Access Hardcoded Credentials", "tactic": "Credential Access"},
            {"technique_id": "AML.T0044", "name": "Full ML Model Access", "tactic": "Privilege Escalation"},
            {"technique_id": "AML.T0048", "name": "Exfiltrate Via ML Inference API", "tactic": "Exfiltration"},
            {"technique_id": "AML.T0053", "name": "Evade ML Model", "tactic": "Defense Evasion"},
            {"technique_id": "AML.T0054", "name": "Prompt Injection", "tactic": "Execution"},
            {"technique_id": "AML.T0056", "name": "LLM Prompt Injection via Indirect Input", "tactic": "Execution"},
        ]
        for t in techniques:
            self._techniques[t["technique_id"]] = t

        self._pattern_map = {
            "ignore all previous instructions": ["AML.T0054"],
            "system prompt": ["AML.T0056"],
            "169.254.169.254": ["AML.T0043"],
            "~/.aws/credentials": ["AML.T0043"],
            "crontab": ["AML.T0040"],
            "nc -lvp": ["AML.T0040"],
            "pip install": ["AML.T0010"],
            "training data": ["AML.T0024"],
        }
