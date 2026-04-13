"""Async compliance report generation worker."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ReportWorker:
    """Generates compliance reports asynchronously."""

    def __init__(self, compliance_service: Any, output_dir: str = "/tmp/reports") -> None:
        self._svc = compliance_service
        self._output_dir = output_dir
        self._queue: asyncio.Queue = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        self._running = False
        await self._queue.put(None)
        if self._task:
            await self._task

    async def enqueue_report(
        self,
        report_id: str,
        framework: str,
        events: List[Dict[str, Any]],
        output_format: str = "json",
    ) -> None:
        await self._queue.put({
            "report_id": report_id,
            "framework": framework,
            "events": events,
            "format": output_format,
        })

    async def _run(self) -> None:
        while True:
            job = await self._queue.get()
            if job is None:
                self._queue.task_done()
                break
            try:
                await self._generate(job)
            except Exception as e:
                logger.error("ReportWorker error: %s", e)
            finally:
                self._queue.task_done()

    async def _generate(self, job: Dict[str, Any]) -> None:
        report_id = job["report_id"]
        framework = job["framework"]
        events = job["events"]
        fmt = job["format"]

        try:
            from ...sdk.agentshield.compliance.reporter import ComplianceReporter
            reporter = ComplianceReporter(organization="AgentShield")

            if framework == "gdpr":
                findings = await self._svc.run_gdpr_check(events)
                reporter.add_section("GDPR", {"findings": [f.to_dict() for f in findings]})
            elif framework == "hipaa":
                findings = await self._svc.run_hipaa_check(events)
                reporter.add_section("HIPAA", {"findings": [f.to_dict() for f in findings]})

            import os
            os.makedirs(self._output_dir, exist_ok=True)
            path = os.path.join(self._output_dir, f"{report_id}.{fmt}")
            if fmt == "pdf":
                reporter.save_pdf(path)
            else:
                reporter.save_json(path)

            logger.info("Report generated: %s", path)
        except Exception as e:
            logger.error("Report generation failed for %s: %s", report_id, e)
