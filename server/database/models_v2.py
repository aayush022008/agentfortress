"""
Extended database models for enterprise features.
Adds Role, Permission, ThreatHunt, HuntResult, ComplianceFinding,
EvidencePackage, AuditLogEntry, Integration, RetentionPolicy,
SavedSearch, DashboardConfig, and more.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    JSON, Boolean, Column, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> float:
    return time.time()


class Role(Base):
    __tablename__ = "roles"
    role_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, default="")
    permissions = Column(JSON, default=list)
    built_in = Column(Boolean, default=False)
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    updated_at = Column(Float, default=_now)


class Permission(Base):
    __tablename__ = "permissions"
    permission_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text, default="")
    category = Column(String(50), default="")


class RoleAssignment(Base):
    __tablename__ = "role_assignments"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "org_id", name="uq_user_role_org"),
    )
    assignment_id = Column(String(36), primary_key=True, default=_uuid)
    user_id = Column(String(36), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.role_id"), nullable=False)
    org_id = Column(String(36), nullable=True)
    assigned_by = Column(String(36), nullable=True)
    assigned_at = Column(Float, default=_now)
    expires_at = Column(Float, nullable=True)


class ThreatHunt(Base):
    __tablename__ = "threat_hunts"
    hunt_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), nullable=False)
    query = Column(Text, nullable=False)
    description = Column(Text, default="")
    schedule = Column(String(100), nullable=True)
    enabled = Column(Boolean, default=True)
    tags = Column(JSON, default=list)
    org_id = Column(String(36), nullable=True)
    created_by = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    last_run_at = Column(Float, nullable=True)
    run_count = Column(Integer, default=0)


class HuntResult(Base):
    __tablename__ = "hunt_results"
    result_id = Column(String(36), primary_key=True, default=_uuid)
    hunt_id = Column(String(36), ForeignKey("threat_hunts.hunt_id"), nullable=True)
    ran_at = Column(Float, default=_now)
    execution_ms = Column(Integer, default=0)
    total_matches = Column(Integer, default=0)
    matches = Column(JSON, default=list)
    errors = Column(JSON, default=list)
    query = Column(Text, default="")


class ComplianceFinding(Base):
    __tablename__ = "compliance_findings"
    finding_id = Column(String(36), primary_key=True, default=_uuid)
    framework = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    category = Column(String(100), default="")
    description = Column(Text, default="")
    recommendation = Column(Text, default="")
    status = Column(String(20), default="open")
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    resolved_at = Column(Float, nullable=True)
    __table_args__ = (Index("ix_cf_framework_status", "framework", "status"),)


class EvidencePackage(Base):
    __tablename__ = "evidence_packages"
    case_id = Column(String(36), primary_key=True)
    investigator = Column(String(200), default="")
    description = Column(Text, default="")
    status = Column(String(20), default="open")
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    sealed_at = Column(Float, nullable=True)
    archive_path = Column(String(500), nullable=True)
    chain_verified = Column(Boolean, default=False)
    metadata = Column(JSON, default=dict)


class AuditLogEntry(Base):
    __tablename__ = "audit_log"
    entry_id = Column(String(36), primary_key=True, default=_uuid)
    action = Column(String(100), nullable=False)
    actor_id = Column(String(36), nullable=False)
    actor_type = Column(String(20), default="user")
    resource_type = Column(String(50), default="")
    resource_id = Column(String(36), default="")
    org_id = Column(String(36), nullable=True)
    details = Column(JSON, default=dict)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    timestamp = Column(Float, default=_now, index=True)
    __table_args__ = (Index("ix_al_actor", "actor_id", "timestamp"),)


class Integration(Base):
    __tablename__ = "integrations"
    integration_id = Column(String(36), primary_key=True, default=_uuid)
    integration_type = Column(String(50), nullable=False)
    name = Column(String(200), nullable=False)
    config = Column(JSON, default=dict)
    enabled = Column(Boolean, default=True)
    org_id = Column(String(36), nullable=True)
    alert_severity_threshold = Column(String(20), default="low")
    created_at = Column(Float, default=_now)
    last_used_at = Column(Float, nullable=True)
    error_count = Column(Integer, default=0)


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    policy_id = Column(String(36), primary_key=True, default=_uuid)
    resource_type = Column(String(50), nullable=False)
    retention_days = Column(Integer, nullable=False)
    archive_before_delete = Column(Boolean, default=True)
    archive_path = Column(String(500), nullable=True)
    org_id = Column(String(36), nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(Float, default=_now)


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    search_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), nullable=False)
    query = Column(Text, nullable=False)
    filters = Column(JSON, default=dict)
    user_id = Column(String(36), nullable=True)
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    last_used_at = Column(Float, nullable=True)
    use_count = Column(Integer, default=0)


class DashboardConfig(Base):
    __tablename__ = "dashboard_configs"
    layout_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(200), default="My Dashboard")
    widgets = Column(JSON, default=list)
    is_default = Column(Boolean, default=False)
    user_id = Column(String(36), nullable=True)
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    updated_at = Column(Float, default=_now)


class IOCRecord(Base):
    __tablename__ = "ioc_records"
    ioc_id = Column(String(36), primary_key=True, default=_uuid)
    ioc_type = Column(String(50), nullable=False)
    value = Column(Text, nullable=False)
    description = Column(Text, default="")
    severity = Column(String(20), default="medium")
    source = Column(String(200), default="")
    tags = Column(JSON, default=list)
    org_id = Column(String(36), nullable=True)
    created_at = Column(Float, default=_now)
    expires_at = Column(Float, nullable=True)
    hit_count = Column(Integer, default=0)
    __table_args__ = (Index("ix_ioc_type_value", "ioc_type", "value"),)
