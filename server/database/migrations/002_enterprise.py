"""
Migration 002 — Enterprise tables.
Creates all new enterprise-grade tables.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

MIGRATION_ID = "002_enterprise"
DESCRIPTION = "Add enterprise tables: roles, RBAC, threat hunts, compliance, forensics, integrations, audit log"


async def upgrade(engine) -> None:
    """Apply migration — create enterprise tables."""
    from ..models_v2 import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Migration %s applied: enterprise tables created", MIGRATION_ID)


async def downgrade(engine) -> None:
    """Rollback migration — drop enterprise tables (DESTRUCTIVE)."""
    tables_to_drop = [
        "ioc_records", "dashboard_configs", "saved_searches",
        "retention_policies", "integrations", "audit_log",
        "evidence_packages", "compliance_findings", "hunt_results",
        "threat_hunts", "role_assignments", "permissions", "roles",
    ]
    async with engine.begin() as conn:
        for table_name in tables_to_drop:
            try:
                await conn.execute(
                    __import__("sqlalchemy", fromlist=["text"]).text(f"DROP TABLE IF EXISTS {table_name}")
                )
                logger.info("Dropped table: %s", table_name)
            except Exception as e:
                logger.warning("Could not drop table %s: %s", table_name, e)
    logger.info("Migration %s rolled back", MIGRATION_ID)
