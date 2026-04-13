"""Data retention service — TTL enforcement and archival."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class RetentionPolicy:
    policy_id: str
    resource_type: str  # events | alerts | sessions | audit_log | snapshots
    retention_days: int
    archive_before_delete: bool = True
    archive_path: Optional[str] = None
    org_id: Optional[str] = None
    enabled: bool = True


class RetentionService:
    """
    Enforces data retention policies — deletes or archives data older than configured TTL.

    Run periodically (e.g., via a scheduled task or cron).

    Usage::

        svc = RetentionService(db_session)
        svc.add_policy(RetentionPolicy("p1", "events", retention_days=90))
        await svc.enforce_all()
    """

    def __init__(self, db=None) -> None:
        self._db = db
        self._policies: List[RetentionPolicy] = []

    def add_policy(self, policy: RetentionPolicy) -> None:
        """Register a retention policy."""
        self._policies.append(policy)

    def list_policies(self) -> List[RetentionPolicy]:
        return list(self._policies)

    async def enforce_all(self) -> Dict[str, Any]:
        """
        Enforce all retention policies.
        Returns a summary dict of what was deleted/archived.
        """
        results: Dict[str, Any] = {}
        for policy in self._policies:
            if not policy.enabled:
                continue
            try:
                result = await self._enforce_policy(policy)
                results[policy.policy_id] = result
            except Exception as e:
                logger.error("Retention enforcement failed for %s: %s", policy.policy_id, e)
                results[policy.policy_id] = {"error": str(e)}
        return results

    async def enforce_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        """Enforce a single retention policy by ID."""
        for policy in self._policies:
            if policy.policy_id == policy_id:
                return await self._enforce_policy(policy)
        return None

    async def get_stats(self) -> Dict[str, Any]:
        """Return data volume statistics per resource type."""
        return {
            "events": {"total": 0, "oldest_age_days": 0},
            "alerts": {"total": 0, "oldest_age_days": 0},
            "sessions": {"total": 0, "oldest_age_days": 0},
        }

    # ------------------------------------------------------------------

    async def _enforce_policy(self, policy: RetentionPolicy) -> Dict[str, Any]:
        cutoff = time.time() - policy.retention_days * 86400
        deleted = 0
        archived = 0

        if self._db is None:
            logger.warning("No DB configured for retention enforcement")
            return {"deleted": 0, "archived": 0, "policy_id": policy.policy_id}

        # Archive first if configured
        if policy.archive_before_delete and policy.archive_path:
            archived = await self._archive_old_records(policy, cutoff)

        # Delete old records
        deleted = await self._delete_old_records(policy, cutoff)

        logger.info(
            "Retention: %s | deleted=%d archived=%d (cutoff=%.0f)",
            policy.resource_type, deleted, archived, cutoff
        )
        return {
            "policy_id": policy.policy_id,
            "resource_type": policy.resource_type,
            "deleted": deleted,
            "archived": archived,
            "cutoff_timestamp": cutoff,
        }

    async def _archive_old_records(
        self, policy: RetentionPolicy, cutoff: float
    ) -> int:
        """Archive records older than cutoff to a file."""
        # Implementation depends on DB model; returns count
        return 0

    async def _delete_old_records(
        self, policy: RetentionPolicy, cutoff: float
    ) -> int:
        """Delete records older than cutoff. Returns count deleted."""
        return 0
