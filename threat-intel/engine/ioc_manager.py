"""IOC (Indicators of Compromise) manager."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class IOC:
    ioc_id: str
    ioc_type: str
    value: str
    description: str = ""
    severity: str = "medium"
    source: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    hit_count: int = 0
    false_positive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "tags": self.tags,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "hit_count": self.hit_count,
        }


class IOCManager:
    """
    Manages IOCs (Indicators of Compromise) for threat detection.

    Supports bulk ingestion from MISP/STIX/CSV, expiry, and hit counting.

    Usage::

        mgr = IOCManager()
        mgr.add("ip", "1.2.3.4", severity="high", source="misp")
        matches = mgr.match_text("connection from 1.2.3.4 port 443")
        mgr.save("/var/agentshield/iocs.json")
    """

    def __init__(self, ioc_file: Optional[str] = None) -> None:
        self._iocs: Dict[str, IOC] = {}
        self._type_index: Dict[str, List[str]] = {}
        if ioc_file and Path(ioc_file).exists():
            self.load(ioc_file)

    def add(
        self,
        ioc_type: str,
        value: str,
        description: str = "",
        severity: str = "medium",
        source: str = "",
        tags: Optional[List[str]] = None,
        ttl_days: Optional[int] = 90,
    ) -> IOC:
        """Add a single IOC."""
        ioc = IOC(
            ioc_id=str(uuid.uuid4()),
            ioc_type=ioc_type,
            value=value,
            description=description,
            severity=severity,
            source=source,
            tags=tags or [],
            expires_at=time.time() + ttl_days * 86400 if ttl_days else None,
        )
        self._iocs[ioc.ioc_id] = ioc
        self._type_index.setdefault(ioc_type, []).append(ioc.ioc_id)
        return ioc

    def add_bulk(self, iocs: List[Dict[str, Any]]) -> int:
        """Bulk ingest IOCs from a list of dicts. Returns count added."""
        count = 0
        for item in iocs:
            try:
                self.add(
                    ioc_type=item.get("type", "string"),
                    value=item["value"],
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    source=item.get("source", ""),
                    tags=item.get("tags", []),
                )
                count += 1
            except (KeyError, ValueError):
                continue
        return count

    def ingest_from_stix_bundle(self, bundle: Dict[str, Any]) -> int:
        """Ingest IOCs from a STIX 2.x bundle."""
        count = 0
        for obj in bundle.get("objects", []):
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                # Extract value from STIX pattern (simplified)
                import re
                m = re.search(r"value\s*=\s*'([^']+)'", pattern)
                if m:
                    self.add(
                        ioc_type="stix",
                        value=m.group(1),
                        description=obj.get("name", ""),
                        severity="medium",
                        source="stix",
                    )
                    count += 1
        return count

    def match_text(self, text: str) -> List[IOC]:
        """Match text against all active IOCs. Returns matching IOCs."""
        now = time.time()
        matches = []
        for ioc in self._iocs.values():
            if ioc.expires_at and ioc.expires_at < now:
                continue
            if ioc.false_positive:
                continue
            if ioc.value.lower() in text.lower():
                ioc.hit_count += 1
                matches.append(ioc)
        return matches

    def match_event(self, event: Dict[str, Any]) -> List[IOC]:
        """Match an event dict against all IOCs."""
        return self.match_text(json.dumps(event, default=str))

    def get_by_type(self, ioc_type: str) -> List[IOC]:
        ids = self._type_index.get(ioc_type, [])
        return [self._iocs[i] for i in ids if i in self._iocs]

    def mark_false_positive(self, ioc_id: str) -> bool:
        ioc = self._iocs.get(ioc_id)
        if ioc:
            ioc.false_positive = True
            return True
        return False

    def cleanup_expired(self) -> int:
        now = time.time()
        expired = [iid for iid, ioc in self._iocs.items() if ioc.expires_at and ioc.expires_at < now]
        for iid in expired:
            del self._iocs[iid]
        return len(expired)

    def save(self, path: str) -> None:
        data = {"iocs": [ioc.to_dict() for ioc in self._iocs.values()]}
        Path(path).write_text(json.dumps(data, indent=2))

    def load(self, path: str) -> int:
        data = json.loads(Path(path).read_text())
        for item in data.get("iocs", []):
            ioc = IOC(**{k: item[k] for k in IOC.__dataclass_fields__ if k in item})
            self._iocs[ioc.ioc_id] = ioc
            self._type_index.setdefault(ioc.ioc_type, []).append(ioc.ioc_id)
        return len(data.get("iocs", []))

    def stats(self) -> Dict[str, Any]:
        active = sum(1 for ioc in self._iocs.values() if not ioc.false_positive)
        return {
            "total": len(self._iocs),
            "active": active,
            "by_type": {t: len(ids) for t, ids in self._type_index.items()},
            "by_severity": {
                s: sum(1 for ioc in self._iocs.values() if ioc.severity == s)
                for s in ("critical", "high", "medium", "low")
            },
        }
