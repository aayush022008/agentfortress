"""Background task queue — asyncio-based job queue."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    job_id: str
    name: str
    status: JobStatus = JobStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "retries": self.retries,
        }


class QueueService:
    """
    In-process asyncio-based task queue for background jobs.
    For production, replace with Celery or RQ backed by Redis.

    Usage::

        queue = QueueService(concurrency=4)
        await queue.start()
        job_id = await queue.enqueue("send_alert", my_async_func, arg1, arg2)
        job = queue.get_job(job_id)
        await queue.stop()
    """

    def __init__(self, concurrency: int = 4) -> None:
        self.concurrency = concurrency
        self._queue: asyncio.Queue = asyncio.Queue()
        self._jobs: Dict[str, Job] = {}
        self._workers: List[asyncio.Task] = []
        self._running = False

    async def start(self) -> None:
        """Start background worker tasks."""
        self._running = True
        for _ in range(self.concurrency):
            task = asyncio.ensure_future(self._worker())
            self._workers.append(task)

    async def stop(self) -> None:
        """Stop all workers gracefully."""
        self._running = False
        for _ in self._workers:
            await self._queue.put(None)  # sentinel
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def enqueue(
        self,
        name: str,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        max_retries: int = 3,
        **kwargs: Any,
    ) -> str:
        """Enqueue a job. Returns job_id."""
        job = Job(job_id=str(uuid.uuid4()), name=name, max_retries=max_retries)
        self._jobs[job.job_id] = job
        await self._queue.put((job, func, args, kwargs))
        return job.job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_jobs(self, status: Optional[JobStatus] = None) -> List[Job]:
        jobs = list(self._jobs.values())
        if status:
            jobs = [j for j in jobs if j.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def queue_size(self) -> int:
        return self._queue.qsize()

    async def _worker(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                self._queue.task_done()
                break
            job, func, args, kwargs = item
            job.status = JobStatus.RUNNING
            job.started_at = time.time()
            try:
                job.result = await func(*args, **kwargs)
                job.status = JobStatus.COMPLETED
            except Exception as e:
                logger.error("Job %s failed: %s", job.job_id, e)
                if job.retries < job.max_retries:
                    job.retries += 1
                    job.status = JobStatus.PENDING
                    await self._queue.put((job, func, args, kwargs))
                else:
                    job.status = JobStatus.FAILED
                    job.error = str(e)
            finally:
                if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                    job.completed_at = time.time()
                self._queue.task_done()
