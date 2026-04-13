"""Policy enforcer service."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from datetime import datetime

from ..database.models import Policy


class PolicyEnforcer:
    """Evaluates events against database-stored policies."""

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def evaluate(self, event: Any) -> str:
        """Return the most severe action triggered by any policy."""
        result = await self._db.execute(
            select(Policy).where(Policy.is_enabled == True)
        )
        policies = result.scalars().all()

        triggered_actions: list[str] = []
        triggered_ids: list[str] = []

        for policy in policies:
            if self._matches(event, policy.condition):
                triggered_actions.append(policy.action)
                triggered_ids.append(policy.id)

        if triggered_ids:
            await self._db.execute(
                update(Policy)
                .where(Policy.id.in_(triggered_ids))
                .values(
                    trigger_count=Policy.trigger_count + 1,
                    last_triggered_at=datetime.utcnow(),
                )
            )

        priority = ["BLOCK", "RATE_LIMIT", "ALERT", "LOG", "ALLOW"]
        for action in priority:
            if action in triggered_actions:
                return action
        return "ALLOW"

    def _matches(self, event: Any, condition: dict) -> bool:
        ctype = condition.get("type")
        if ctype == "threat_score_above":
            return event.threat_score >= condition.get("threshold", 50)
        elif ctype == "event_type":
            return event.event_type in condition.get("event_types", [])
        elif ctype == "output_size_above":
            size = event.data.get("output_size_bytes", 0) or event.data.get("result_size_bytes", 0)
            return size >= condition.get("threshold_bytes", 100000)
        elif ctype == "and":
            return all(self._matches(event, c) for c in condition.get("conditions", []))
        elif ctype == "or":
            return any(self._matches(event, c) for c in condition.get("conditions", []))
        return False
