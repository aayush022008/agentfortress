"""
Sandbox executor — run agents in isolated subprocesses with resource limits.
Supports CPU%, memory MB, max duration, and optional container isolation.
"""
from __future__ import annotations

import asyncio
import json
import os
import resource
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import psutil


@dataclass
class SandboxConfig:
    """Configuration for a sandboxed agent execution."""

    max_cpu_percent: float = 80.0
    """Maximum CPU utilisation (%) before the process is throttled/killed."""

    max_memory_mb: int = 512
    """Maximum RSS memory in megabytes."""

    max_duration_seconds: float = 300.0
    """Wall-clock timeout in seconds."""

    allowed_env_vars: List[str] = field(default_factory=list)
    """Whitelist of environment variables to pass to the child process."""

    working_dir: Optional[str] = None
    """Working directory for the child process; None = temp dir."""

    enable_network: bool = True
    """Whether to allow network access (requires network policy for fine-grained control)."""

    capture_output: bool = True
    """Whether to capture stdout/stderr."""

    extra_args: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SandboxResult:
    """Result of a sandboxed execution."""

    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    peak_memory_mb: float
    peak_cpu_percent: float
    killed_by_oom: bool = False
    killed_by_timeout: bool = False
    killed_by_cpu: bool = False
    events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        """Return True if execution completed without forced termination."""
        return self.exit_code == 0 and not (
            self.killed_by_oom or self.killed_by_timeout or self.killed_by_cpu
        )


class SandboxExecutor:
    """
    Executes an agent script or callable in an isolated subprocess with
    resource limits (CPU, memory, time).

    Usage::

        config = SandboxConfig(max_memory_mb=256, max_duration_seconds=60)
        executor = SandboxExecutor(config)
        result = await executor.run_script("path/to/agent.py", args=["--task", "foo"])
    """

    def __init__(self, config: Optional[SandboxConfig] = None) -> None:
        self.config = config or SandboxConfig()
        self._monitoring_task: Optional[asyncio.Task] = None  # type: ignore[type-arg]

    async def run_script(
        self,
        script_path: str,
        args: Optional[List[str]] = None,
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """Run a Python script in a sandboxed subprocess."""
        cmd = [sys.executable, script_path] + (args or [])
        return await self._run_process(cmd, env_overrides=env_overrides)

    async def run_module(
        self,
        module: str,
        args: Optional[List[str]] = None,
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """Run a Python module (python -m <module>) in a sandboxed subprocess."""
        cmd = [sys.executable, "-m", module] + (args or [])
        return await self._run_process(cmd, env_overrides=env_overrides)

    async def run_callable(
        self,
        func: Callable[..., Any],
        *func_args: Any,
        **func_kwargs: Any,
    ) -> SandboxResult:
        """
        Serialize a callable + arguments and execute it in a child process.
        The function must be importable (top-level in a module).
        """
        import pickle
        import tempfile

        payload = pickle.dumps((func, func_args, func_kwargs))
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pkl") as f:
            f.write(payload)
            payload_path = f.name

        runner_code = f"""
import pickle, sys
with open({payload_path!r}, "rb") as f:
    func, args, kwargs = pickle.load(f)
result = func(*args, **kwargs)
print(result)
"""
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=".py", mode="w"
        ) as f:
            f.write(runner_code)
            script_path = f.name

        try:
            return await self.run_script(script_path)
        finally:
            os.unlink(payload_path)
            os.unlink(script_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_env(
        self, env_overrides: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """Build a filtered environment for the child process."""
        cfg = self.config
        if cfg.allowed_env_vars:
            base_env = {
                k: v
                for k, v in os.environ.items()
                if k in cfg.allowed_env_vars
            }
        else:
            # Pass a minimal safe set
            safe_keys = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR"}
            base_env = {k: v for k, v in os.environ.items() if k in safe_keys}

        if env_overrides:
            base_env.update(env_overrides)

        if not self.config.enable_network:
            # Signal to child that network should be blocked (child-side policy)
            base_env["AGENTSHIELD_SANDBOX_NO_NET"] = "1"

        return base_env

    async def _run_process(
        self,
        cmd: List[str],
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """Core execution loop with resource monitoring."""
        env = self._build_env(env_overrides)
        cwd = self.config.working_dir or None

        stdout_pipe = asyncio.subprocess.PIPE if self.config.capture_output else None
        stderr_pipe = asyncio.subprocess.PIPE if self.config.capture_output else None

        start_time = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=stdout_pipe,
            stderr=stderr_pipe,
            env=env,
            cwd=cwd,
            preexec_fn=self._preexec_fn,
        )

        peak_memory_mb: float = 0.0
        peak_cpu_percent: float = 0.0
        killed_by_oom = False
        killed_by_timeout = False
        killed_by_cpu = False
        events: List[Dict[str, Any]] = []

        async def monitor() -> None:
            nonlocal peak_memory_mb, peak_cpu_percent
            nonlocal killed_by_oom, killed_by_timeout, killed_by_cpu

            try:
                ps_proc = psutil.Process(proc.pid)
            except psutil.NoSuchProcess:
                return

            while True:
                await asyncio.sleep(0.5)
                elapsed = time.monotonic() - start_time

                try:
                    mem_mb = ps_proc.memory_info().rss / 1_048_576
                    cpu_pct = ps_proc.cpu_percent(interval=None)
                except psutil.NoSuchProcess:
                    break

                peak_memory_mb = max(peak_memory_mb, mem_mb)
                peak_cpu_percent = max(peak_cpu_percent, cpu_pct)

                if elapsed > self.config.max_duration_seconds:
                    killed_by_timeout = True
                    events.append(
                        {"type": "sandbox.timeout", "elapsed": elapsed}
                    )
                    proc.kill()
                    break

                if mem_mb > self.config.max_memory_mb:
                    killed_by_oom = True
                    events.append(
                        {"type": "sandbox.oom", "memory_mb": mem_mb}
                    )
                    proc.kill()
                    break

                if cpu_pct > self.config.max_cpu_percent:
                    killed_by_cpu = True
                    events.append(
                        {"type": "sandbox.cpu_limit", "cpu_pct": cpu_pct}
                    )
                    proc.kill()
                    break

        monitor_task = asyncio.ensure_future(monitor())

        try:
            stdout_bytes, stderr_bytes = await proc.communicate()
        finally:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass

        duration = time.monotonic() - start_time

        return SandboxResult(
            exit_code=proc.returncode or 0,
            stdout=(stdout_bytes or b"").decode(errors="replace"),
            stderr=(stderr_bytes or b"").decode(errors="replace"),
            duration_seconds=duration,
            peak_memory_mb=peak_memory_mb,
            peak_cpu_percent=peak_cpu_percent,
            killed_by_oom=killed_by_oom,
            killed_by_timeout=killed_by_timeout,
            killed_by_cpu=killed_by_cpu,
            events=events,
        )

    @staticmethod
    def _preexec_fn() -> None:
        """Called in the child process before exec — sets resource limits."""
        # Prevent core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # New process group so we can kill the whole tree
        os.setsid()
