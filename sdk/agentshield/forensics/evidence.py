"""
Evidence package — bundle logs, snapshots, and metadata for legal hold.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tarfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceItem:
    item_id: str
    item_type: str  # log | snapshot | event | metadata | artifact
    description: str
    file_path: Optional[str]
    content: Optional[Dict[str, Any]]
    sha256: Optional[str] = None
    added_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "item_type": self.item_type,
            "description": self.description,
            "file_path": self.file_path,
            "sha256": self.sha256,
            "added_at": self.added_at,
        }


class EvidencePackage:
    """
    Bundles evidence (logs, snapshots, events) into a tamper-evident archive
    for legal hold and forensic analysis.

    The package is a tar.gz archive with:
    - manifest.json — inventory with SHA-256 hashes of every file
    - items/ — all evidence files
    - metadata.json — case metadata

    Usage::

        pkg = EvidencePackage(case_id="CASE-2024-001", investigator="alice@corp.com")
        pkg.add_log_file("/var/log/agentshield/audit.log", "Main audit log")
        pkg.add_events(events, "Session events for incident")
        pkg.add_snapshot(snapshot, "Agent state at time of incident")
        archive_path = pkg.seal("/output/evidence-case-001.tar.gz")
    """

    def __init__(
        self,
        case_id: Optional[str] = None,
        investigator: str = "",
        description: str = "",
    ) -> None:
        self.case_id = case_id or f"CASE-{uuid.uuid4().hex[:8].upper()}"
        self.investigator = investigator
        self.description = description
        self.created_at = time.time()
        self._items: List[EvidenceItem] = []
        self._work_dir = Path(f"/tmp/evidence_{self.case_id}")
        self._work_dir.mkdir(parents=True, exist_ok=True)
        (self._work_dir / "items").mkdir(exist_ok=True)

    def add_log_file(self, path: str, description: str = "") -> EvidenceItem:
        """Add a log file to the package."""
        src = Path(path)
        if not src.exists():
            raise FileNotFoundError(f"Log file not found: {path}")
        dest = self._work_dir / "items" / src.name
        shutil.copy2(str(src), str(dest))
        sha256 = self._hash_file(str(dest))
        item = EvidenceItem(
            item_id=str(uuid.uuid4()),
            item_type="log",
            description=description or src.name,
            file_path=src.name,
            content=None,
            sha256=sha256,
        )
        self._items.append(item)
        return item

    def add_events(
        self, events: List[Dict[str, Any]], description: str = ""
    ) -> EvidenceItem:
        """Add a list of events as a JSON file."""
        filename = f"events_{uuid.uuid4().hex[:8]}.json"
        dest = self._work_dir / "items" / filename
        dest.write_text(json.dumps(events, indent=2, default=str))
        sha256 = self._hash_file(str(dest))
        item = EvidenceItem(
            item_id=str(uuid.uuid4()),
            item_type="event",
            description=description or "Agent events",
            file_path=filename,
            content=None,
            sha256=sha256,
        )
        self._items.append(item)
        return item

    def add_snapshot(self, snapshot: Any, description: str = "") -> EvidenceItem:
        """Add an agent snapshot."""
        if hasattr(snapshot, "to_dict"):
            data = snapshot.to_dict()
        else:
            data = snapshot
        filename = f"snapshot_{uuid.uuid4().hex[:8]}.json"
        dest = self._work_dir / "items" / filename
        dest.write_text(json.dumps(data, indent=2, default=str))
        sha256 = self._hash_file(str(dest))
        item = EvidenceItem(
            item_id=str(uuid.uuid4()),
            item_type="snapshot",
            description=description or "Agent state snapshot",
            file_path=filename,
            content=None,
            sha256=sha256,
        )
        self._items.append(item)
        return item

    def add_metadata(self, metadata: Dict[str, Any], description: str = "") -> EvidenceItem:
        """Add arbitrary metadata."""
        item = EvidenceItem(
            item_id=str(uuid.uuid4()),
            item_type="metadata",
            description=description,
            file_path=None,
            content=metadata,
        )
        self._items.append(item)
        return item

    def seal(self, output_path: str) -> str:
        """
        Finalize and create the evidence archive.
        Returns the path to the created .tar.gz file.
        """
        # Write manifest
        manifest = {
            "case_id": self.case_id,
            "investigator": self.investigator,
            "description": self.description,
            "sealed_at": time.time(),
            "items": [item.to_dict() for item in self._items],
        }
        manifest_path = self._work_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        # Compute manifest hash
        manifest_hash = self._hash_file(str(manifest_path))
        manifest["manifest_sha256"] = manifest_hash
        manifest_path.write_text(json.dumps(manifest, indent=2))

        # Write metadata
        meta_path = self._work_dir / "metadata.json"
        meta_path.write_text(json.dumps({
            "case_id": self.case_id,
            "created_at": self.created_at,
            "sealed_at": time.time(),
            "investigator": self.investigator,
            "agentshield_version": "2.0.0",
        }, indent=2))

        # Create archive
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(str(out), "w:gz") as tar:
            tar.add(str(self._work_dir), arcname=self.case_id)

        return str(out)

    def cleanup(self) -> None:
        """Remove the temporary working directory."""
        shutil.rmtree(str(self._work_dir), ignore_errors=True)

    # ------------------------------------------------------------------

    @staticmethod
    def _hash_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
