"""
Structured audit logger for AgentShield.

Writes all intercepted events to a structured JSONL audit log file.
Supports rotation and provides tamper-evident logging.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Writes structured audit logs for all agent events.

    Log format is JSONL (one JSON object per line) for easy parsing.
    Each entry includes a chain hash for tamper detection.
    """

    def __init__(
        self,
        log_path: str = "agentshield-audit.log",
        max_size_bytes: int = 100 * 1024 * 1024,  # 100MB
    ) -> None:
        self._log_path = Path(log_path)
        self._max_size_bytes = max_size_bytes
        self._lock = threading.Lock()
        self._file = open(self._log_path, "a", encoding="utf-8")
        self._last_hash = "genesis"
        self._entry_count = 0

    def log(self, event: Any) -> None:
        """
        Write an event to the audit log.

        Args:
            event: InterceptorEvent to log
        """
        entry = self._build_entry(event)
        line = json.dumps(entry, separators=(",", ":")) + "\n"

        with self._lock:
            try:
                self._file.write(line)
                self._file.flush()
                self._entry_count += 1

                # Rotate if needed
                if self._log_path.stat().st_size > self._max_size_bytes:
                    self._rotate()

            except OSError as e:
                logger.error(f"Audit log write error: {e}")

    def _build_entry(self, event: Any) -> dict:
        """Build a log entry dict from an event."""
        entry = {
            "event_id": event.event_id,
            "session_id": event.session_id,
            "event_type": event.event_type.value,
            "agent_name": event.agent_name,
            "timestamp": event.timestamp,
            "threat_score": event.threat_score,
            "blocked": event.blocked,
            "data_keys": list(event.data.keys()),  # Log keys but not values for sensitive data
        }

        # Include non-sensitive data
        safe_keys = {"model", "tool_name", "event_type", "input_tokens", "output_tokens", "latency_ms"}
        for key in safe_keys:
            if key in event.data:
                entry[key] = event.data[key]

        # Chain hash for tamper detection
        content = json.dumps(entry, sort_keys=True)
        chain_input = f"{self._last_hash}:{content}"
        self._last_hash = hashlib.sha256(chain_input.encode()).hexdigest()[:16]
        entry["chain_hash"] = self._last_hash

        return entry

    def _rotate(self) -> None:
        """Rotate the log file."""
        self._file.close()
        rotated_path = self._log_path.with_suffix(
            f".{int(time.time())}.log"
        )
        self._log_path.rename(rotated_path)
        self._file = open(self._log_path, "a", encoding="utf-8")
        self._last_hash = "genesis"
        logger.info(f"Audit log rotated to {rotated_path}")

    def close(self) -> None:
        """Close the log file."""
        with self._lock:
            self._file.flush()
            self._file.close()

    def get_entries(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Read entries from the audit log.

        Args:
            session_id: Filter by session ID
            limit: Maximum entries to return

        Returns:
            List of log entry dicts
        """
        entries: list[dict] = []
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if session_id and entry.get("session_id") != session_id:
                            continue
                        entries.append(entry)
                        if len(entries) >= limit:
                            break
                    except json.JSONDecodeError:
                        pass
        except FileNotFoundError:
            pass
        return entries

    def verify_chain(self) -> tuple[bool, str]:
        """
        Verify the chain hash integrity of the audit log.

        Returns:
            Tuple of (is_valid, message)
        """
        last_hash = "genesis"
        line_num = 0
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    line_num += 1
                    try:
                        entry = json.loads(line)
                        stored_hash = entry.pop("chain_hash", None)
                        content = json.dumps(entry, sort_keys=True)
                        chain_input = f"{last_hash}:{content}"
                        computed = hashlib.sha256(chain_input.encode()).hexdigest()[:16]
                        if stored_hash != computed:
                            return False, f"Chain hash mismatch at line {line_num}"
                        last_hash = computed
                    except json.JSONDecodeError:
                        return False, f"Invalid JSON at line {line_num}"
        except FileNotFoundError:
            return True, "No log file found"

        return True, f"Chain valid ({line_num} entries)"
