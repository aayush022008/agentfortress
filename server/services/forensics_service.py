"""Forensics service — evidence packaging and chain of custody management."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class EvidencePackageMeta:
    case_id: str
    investigator: str
    description: str
    status: str = "open"  # open | sealed | archived
    created_at: float = field(default_factory=time.time)
    sealed_at: Optional[float] = None
    archive_path: Optional[str] = None
    chain_verified: bool = False


class ForensicsService:
    """
    Server-side forensics service — manages evidence packages and chain of custody.
    """

    def __init__(self, storage_dir: str = "/tmp/agentshield/forensics") -> None:
        self._storage_dir = Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._packages: Dict[str, EvidencePackageMeta] = {}

    def create_package(
        self,
        investigator: str = "",
        description: str = "",
        case_id: Optional[str] = None,
    ) -> EvidencePackageMeta:
        meta = EvidencePackageMeta(
            case_id=case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}",
            investigator=investigator,
            description=description,
        )
        self._packages[meta.case_id] = meta
        return meta

    def list_packages(self) -> List[EvidencePackageMeta]:
        return sorted(self._packages.values(), key=lambda p: p.created_at, reverse=True)

    def get_package(self, case_id: str) -> Optional[EvidencePackageMeta]:
        return self._packages.get(case_id)

    def seal_package(
        self,
        case_id: str,
        events: List[Dict[str, Any]],
        snapshots: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        """Seal the evidence package and return the archive path."""
        meta = self._packages.get(case_id)
        if not meta:
            return None

        try:
            from ...sdk.agentshield.forensics.evidence import EvidencePackage
            pkg = EvidencePackage(case_id=case_id, investigator=meta.investigator, description=meta.description)
            if events:
                pkg.add_events(events, "Session events")
            if snapshots:
                for snap in snapshots:
                    pkg.add_snapshot(snap, "Agent state snapshot")

            archive_path = str(self._storage_dir / f"{case_id}.tar.gz")
            pkg.seal(archive_path)
            pkg.cleanup()

            meta.status = "sealed"
            meta.sealed_at = time.time()
            meta.archive_path = archive_path

            return archive_path
        except Exception as e:
            meta.status = "error"
            raise

    def verify_chain(self, case_id: str) -> bool:
        """Verify chain of custody for a package."""
        coc_path = self._storage_dir / f"{case_id}_coc.json"
        if not coc_path.exists():
            return False
        try:
            from ...sdk.agentshield.forensics.chain_of_custody import ChainOfCustody
            coc = ChainOfCustody.load(str(coc_path))
            result = coc.verify()
            if case_id in self._packages:
                self._packages[case_id].chain_verified = result
            return result
        except Exception:
            return False
