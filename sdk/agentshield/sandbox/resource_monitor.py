"""
Real-time resource monitor for sandboxed agents.
Tracks CPU, memory, and network I/O for a given process.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

import psutil


@dataclass
class ResourceSnapshot:
    """Point-in-time resource usage for a process."""

    timestamp: float
    cpu_percent: float
    memory_rss_mb: float
    memory_vms_mb: float
    net_bytes_sent: int
    net_bytes_recv: int
    open_files: int
    threads: int
    pid: int

    def to_dict(self) -> Dict[str, float | int]:
        return {
            "timestamp": self.timestamp,
            "cpu_percent": self.cpu_percent,
            "memory_rss_mb": self.memory_rss_mb,
            "memory_vms_mb": self.memory_vms_mb,
            "net_bytes_sent": self.net_bytes_sent,
            "net_bytes_recv": self.net_bytes_recv,
            "open_files": self.open_files,
            "threads": self.threads,
            "pid": self.pid,
        }


class ResourceMonitor:
    """
    Asynchronously monitors a running process and emits snapshots at a
    configurable interval.  Triggers callbacks on threshold violations.

    Usage::

        monitor = ResourceMonitor(pid=proc.pid, interval=1.0)
        monitor.on_violation(lambda snap, reason: print(reason, snap))
        await monitor.start()
        ...
        await monitor.stop()
        history = monitor.history
    """

    def __init__(
        self,
        pid: int,
        interval: float = 1.0,
        max_memory_mb: Optional[float] = None,
        max_cpu_percent: Optional[float] = None,
    ) -> None:
        self.pid = pid
        self.interval = interval
        self.max_memory_mb = max_memory_mb
        self.max_cpu_percent = max_cpu_percent

        self.history: List[ResourceSnapshot] = []
        self._violation_callbacks: List[
            Callable[[ResourceSnapshot, str], None]
        ] = []
        self._task: Optional[asyncio.Task] = None  # type: ignore[type-arg]
        self._running = False

    def on_violation(
        self, callback: Callable[[ResourceSnapshot, str], None]
    ) -> None:
        """Register a callback called when a resource limit is exceeded."""
        self._violation_callbacks.append(callback)

    async def start(self) -> None:
        """Start background monitoring."""
        self._running = True
        self._task = asyncio.ensure_future(self._monitor_loop())

    async def stop(self) -> None:
        """Stop background monitoring and await the task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def snapshot_now(self) -> Optional[ResourceSnapshot]:
        """Take a single synchronous snapshot of the process."""
        try:
            ps = psutil.Process(self.pid)
            mem = ps.memory_info()
            net = psutil.net_io_counters()
            snap = ResourceSnapshot(
                timestamp=time.time(),
                cpu_percent=ps.cpu_percent(interval=0.1),
                memory_rss_mb=mem.rss / 1_048_576,
                memory_vms_mb=mem.vms / 1_048_576,
                net_bytes_sent=net.bytes_sent,
                net_bytes_recv=net.bytes_recv,
                open_files=len(ps.open_files()),
                threads=ps.num_threads(),
                pid=self.pid,
            )
            return snap
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def peak_memory_mb(self) -> float:
        """Return peak RSS memory across all recorded snapshots."""
        if not self.history:
            return 0.0
        return max(s.memory_rss_mb for s in self.history)

    def peak_cpu_percent(self) -> float:
        """Return peak CPU% across all recorded snapshots."""
        if not self.history:
            return 0.0
        return max(s.cpu_percent for s in self.history)

    def summary(self) -> Dict[str, float]:
        """Return a summary dict of resource usage statistics."""
        if not self.history:
            return {}
        memories = [s.memory_rss_mb for s in self.history]
        cpus = [s.cpu_percent for s in self.history]
        return {
            "peak_memory_mb": max(memories),
            "avg_memory_mb": sum(memories) / len(memories),
            "peak_cpu_percent": max(cpus),
            "avg_cpu_percent": sum(cpus) / len(cpus),
            "snapshots": len(self.history),
            "duration_seconds": self.history[-1].timestamp - self.history[0].timestamp
            if len(self.history) > 1
            else 0.0,
        }

    # ------------------------------------------------------------------

    async def _monitor_loop(self) -> None:
        try:
            ps = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            return

        # Kick off cpu_percent measurement
        ps.cpu_percent(interval=None)

        while self._running:
            await asyncio.sleep(self.interval)
            try:
                mem = ps.memory_info()
                cpu = ps.cpu_percent(interval=None)
                net = psutil.net_io_counters()
                snap = ResourceSnapshot(
                    timestamp=time.time(),
                    cpu_percent=cpu,
                    memory_rss_mb=mem.rss / 1_048_576,
                    memory_vms_mb=mem.vms / 1_048_576,
                    net_bytes_sent=net.bytes_sent,
                    net_bytes_recv=net.bytes_recv,
                    open_files=len(ps.open_files()),
                    threads=ps.num_threads(),
                    pid=self.pid,
                )
                self.history.append(snap)
                self._check_thresholds(snap)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break

    def _check_thresholds(self, snap: ResourceSnapshot) -> None:
        if self.max_memory_mb and snap.memory_rss_mb > self.max_memory_mb:
            self._fire(snap, f"memory_exceeded:{snap.memory_rss_mb:.1f}MB")
        if self.max_cpu_percent and snap.cpu_percent > self.max_cpu_percent:
            self._fire(snap, f"cpu_exceeded:{snap.cpu_percent:.1f}%")

    def _fire(self, snap: ResourceSnapshot, reason: str) -> None:
        for cb in self._violation_callbacks:
            try:
                cb(snap, reason)
            except Exception:
                pass
