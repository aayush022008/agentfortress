"""Threat hunter service — saved hunts, scheduled execution, IOC matching."""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SavedHunt:
    hunt_id: str
    name: str
    query: str
    description: str = ""
    schedule: Optional[str] = None
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_run_at: Optional[float] = None
    run_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "query": self.query,
            "description": self.description,
            "schedule": self.schedule,
            "enabled": self.enabled,
            "tags": self.tags,
            "created_at": self.created_at,
            "last_run_at": self.last_run_at,
            "run_count": self.run_count,
        }


@dataclass
class HuntResult:
    result_id: str
    hunt_id: str
    ran_at: float
    execution_ms: int
    total_matches: int
    matches: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class IOC:
    ioc_id: str
    ioc_type: str  # ip | domain | hash | url | pattern | tool_name
    value: str
    description: str = ""
    severity: str = "medium"
    source: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    hit_count: int = 0


class ThreatHunterService:
    """
    Manages saved threat hunts and IOC matching against agent events.

    Hunt queries use a simplified SQL-like syntax:
        SELECT * FROM events WHERE tool_name = 'bash' AND session_duration > 300
        SELECT * FROM alerts WHERE severity = 'critical'
    """

    def __init__(self) -> None:
        self._hunts: Dict[str, SavedHunt] = {}
        self._iocs: Dict[str, IOC] = {}
        self._results: Dict[str, HuntResult] = {}

    def create_hunt(
        self,
        name: str,
        query: str,
        description: str = "",
        schedule: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> SavedHunt:
        hunt = SavedHunt(
            hunt_id=str(uuid.uuid4()),
            name=name,
            query=query,
            description=description,
            schedule=schedule,
            tags=tags or [],
        )
        self._hunts[hunt.hunt_id] = hunt
        return hunt

    def get_hunt(self, hunt_id: str) -> Optional[SavedHunt]:
        return self._hunts.get(hunt_id)

    def list_hunts(self, enabled_only: bool = False) -> List[SavedHunt]:
        hunts = list(self._hunts.values())
        if enabled_only:
            hunts = [h for h in hunts if h.enabled]
        return sorted(hunts, key=lambda h: h.created_at, reverse=True)

    def delete_hunt(self, hunt_id: str) -> bool:
        return bool(self._hunts.pop(hunt_id, None))

    def run_hunt(
        self,
        hunt_id: str,
        events: List[Dict[str, Any]],
    ) -> Optional[HuntResult]:
        hunt = self._hunts.get(hunt_id)
        if not hunt:
            return None
        return self.execute_query(hunt.query, events, hunt_id=hunt_id)

    def execute_query(
        self,
        query: str,
        events: List[Dict[str, Any]],
        hunt_id: Optional[str] = None,
    ) -> HuntResult:
        """Execute a hunt query against a list of events."""
        start = time.time()
        matches: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            # Parse simple WHERE clause
            filter_fn = self._parse_query(query)
            matches = [e for e in events if filter_fn(e)]
        except Exception as e:
            errors.append(str(e))

        result = HuntResult(
            result_id=str(uuid.uuid4()),
            hunt_id=hunt_id or "adhoc",
            ran_at=time.time(),
            execution_ms=int((time.time() - start) * 1000),
            total_matches=len(matches),
            matches=matches[:1000],
            errors=errors,
        )
        self._results[result.result_id] = result

        if hunt_id and hunt_id in self._hunts:
            self._hunts[hunt_id].last_run_at = time.time()
            self._hunts[hunt_id].run_count += 1

        return result

    # IOC management
    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str = "",
        severity: str = "medium",
        source: str = "",
        tags: Optional[List[str]] = None,
        ttl_days: Optional[int] = None,
    ) -> IOC:
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
        return ioc

    def match_iocs(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match IOCs against events. Returns list of matches."""
        # Remove expired IOCs
        now = time.time()
        active_iocs = [
            ioc for ioc in self._iocs.values()
            if ioc.expires_at is None or ioc.expires_at > now
        ]

        hits: List[Dict[str, Any]] = []
        for event in events:
            event_str = str(event)
            for ioc in active_iocs:
                if ioc.value in event_str:
                    ioc.hit_count += 1
                    hits.append({
                        "event": event,
                        "ioc": ioc.ioc_id,
                        "ioc_type": ioc.ioc_type,
                        "ioc_value": ioc.value,
                        "severity": ioc.severity,
                    })
        return hits

    def list_iocs(self) -> List[IOC]:
        return list(self._iocs.values())

    # ------------------------------------------------------------------

    def _parse_query(self, query: str):
        """Parse a simple SQL-like query into a filter function."""
        # Extract WHERE clause
        where_match = re.search(r"WHERE\s+(.+?)(?:LIMIT|ORDER|$)", query, re.IGNORECASE | re.DOTALL)
        if not where_match:
            return lambda e: True

        where_clause = where_match.group(1).strip()

        # Parse conditions: field = 'value', field > number, field LIKE '%pattern%'
        conditions = re.split(r"\s+AND\s+", where_clause, flags=re.IGNORECASE)

        def matches_condition(event: Dict[str, Any], cond: str) -> bool:
            # field = 'value'
            m = re.match(r"(\w+)\s*=\s*'([^']*)'", cond.strip())
            if m:
                field, value = m.group(1), m.group(2)
                return str(event.get(field, "")).lower() == value.lower()

            # field > number
            m = re.match(r"(\w+)\s*([><=!]+)\s*(\d+(?:\.\d+)?)", cond.strip())
            if m:
                field, op, val = m.group(1), m.group(2), float(m.group(3))
                fval = float(event.get(field, 0) or 0)
                ops = {">": fval > val, "<": fval < val, ">=": fval >= val, "<=": fval <= val, "=": fval == val}
                return ops.get(op, False)

            # field LIKE '%pattern%'
            m = re.match(r"(\w+)\s+LIKE\s+'([^']*)'", cond.strip(), re.IGNORECASE)
            if m:
                field, pattern = m.group(1), m.group(2)
                regex = pattern.replace("%", ".*").replace("_", ".")
                return bool(re.search(regex, str(event.get(field, "")), re.IGNORECASE))

            return False

        def filter_fn(event: Dict[str, Any]) -> bool:
            return all(matches_condition(event, c) for c in conditions)

        return filter_fn
