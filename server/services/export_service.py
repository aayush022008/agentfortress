"""Data export pipeline service."""
from __future__ import annotations

import csv
import io
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class ExportJob:
    job_id: str
    resource: str
    format: str
    status: str = "pending"
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    record_count: int = 0
    file_path: Optional[str] = None
    error: Optional[str] = None


class ExportService:
    """
    Exports AgentShield data in multiple formats: JSON, NDJSON, CSV, PDF.

    Usage::

        svc = ExportService(output_dir="/tmp/exports")
        job = await svc.export_events(events, format="csv")
        print(job.file_path)
    """

    def __init__(self, output_dir: str = "/tmp/agentshield/exports") -> None:
        import os
        os.makedirs(output_dir, exist_ok=True)
        self._output_dir = output_dir
        self._jobs: Dict[str, ExportJob] = {}

    def export_json(
        self, data: List[Dict[str, Any]], filename: Optional[str] = None
    ) -> str:
        """Export data as a JSON array. Returns file path."""
        path = self._make_path(filename or f"export-{uuid.uuid4().hex[:8]}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def export_ndjson(
        self, data: List[Dict[str, Any]], filename: Optional[str] = None
    ) -> str:
        """Export data as NDJSON (one JSON object per line). Returns file path."""
        path = self._make_path(filename or f"export-{uuid.uuid4().hex[:8]}.ndjson")
        with open(path, "w") as f:
            for record in data:
                f.write(json.dumps(record, default=str) + "\n")
        return path

    def export_csv(
        self,
        data: List[Dict[str, Any]],
        fields: Optional[List[str]] = None,
        filename: Optional[str] = None,
    ) -> str:
        """Export data as CSV. Returns file path."""
        if not data:
            path = self._make_path(filename or f"export-{uuid.uuid4().hex[:8]}.csv")
            open(path, "w").close()
            return path

        path = self._make_path(filename or f"export-{uuid.uuid4().hex[:8]}.csv")
        fieldnames = fields or list(data[0].keys())

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for record in data:
                writer.writerow({k: str(record.get(k, "")) for k in fieldnames})
        return path

    def stream_ndjson(
        self, data: Iterator[Dict[str, Any]]
    ) -> Iterator[bytes]:
        """Stream NDJSON records as bytes. Use with StreamingResponse."""
        for record in data:
            yield (json.dumps(record, default=str) + "\n").encode("utf-8")

    def stream_csv(
        self,
        data: Iterator[Dict[str, Any]],
        fields: Optional[List[str]] = None,
    ) -> Iterator[bytes]:
        """Stream CSV records as bytes."""
        buf = io.StringIO()
        writer = None
        for record in data:
            if writer is None:
                fieldnames = fields or list(record.keys())
                writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                yield buf.getvalue().encode("utf-8")
                buf.seek(0)
                buf.truncate()
            writer.writerow({k: str(record.get(k, "")) for k in writer.fieldnames})
            yield buf.getvalue().encode("utf-8")
            buf.seek(0)
            buf.truncate()

    def create_job(self, resource: str, format: str) -> ExportJob:
        job = ExportJob(
            job_id=str(uuid.uuid4()),
            resource=resource,
            format=format,
        )
        self._jobs[job.job_id] = job
        return job

    def get_job(self, job_id: str) -> Optional[ExportJob]:
        return self._jobs.get(job_id)

    # ------------------------------------------------------------------

    def _make_path(self, filename: str) -> str:
        import os
        return os.path.join(self._output_dir, filename)
