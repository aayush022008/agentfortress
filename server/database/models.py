"""
Database models for AgentShield Server.

Uses SQLAlchemy ORM with support for both SQLite (dev) and PostgreSQL (prod).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def gen_uuid() -> str:
    return str(uuid.uuid4())


class Organization(Base):
    __tablename__ = "organizations"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    name: str = Column(String(255), nullable=False, unique=True)
    slug: str = Column(String(100), nullable=False, unique=True)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    updated_at: datetime = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active: bool = Column(Boolean, default=True)
    settings: dict = Column(JSON, default=dict)

    api_keys = relationship("ApiKey", back_populates="organization", cascade="all, delete-orphan")
    sessions = relationship("AgentSession", back_populates="organization")
    policies = relationship("Policy", back_populates="organization")
    alerts = relationship("Alert", back_populates="organization")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    organization_id: str = Column(String(36), ForeignKey("organizations.id"), nullable=False)
    name: str = Column(String(255), nullable=False)
    key_hash: str = Column(String(64), nullable=False, unique=True)
    key_prefix: str = Column(String(10), nullable=False)  # First 8 chars for display
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    last_used_at: Optional[datetime] = Column(DateTime, nullable=True)
    expires_at: Optional[datetime] = Column(DateTime, nullable=True)
    is_active: bool = Column(Boolean, default=True)
    scopes: list = Column(JSON, default=list)  # ["read", "write", "admin"]

    organization = relationship("Organization", back_populates="api_keys")


class AgentSession(Base):
    __tablename__ = "agent_sessions"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Optional[str] = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    agent_name: str = Column(String(255), nullable=False)
    status: str = Column(String(50), default="active")  # active, completed, blocked, error, killed
    started_at: datetime = Column(DateTime, default=datetime.utcnow)
    ended_at: Optional[datetime] = Column(DateTime, nullable=True)
    environment: str = Column(String(50), default="development")
    framework: str = Column(String(100), default="unknown")  # langchain, crewai, etc.
    total_events: int = Column(Integer, default=0)
    total_llm_calls: int = Column(Integer, default=0)
    total_tool_calls: int = Column(Integer, default=0)
    total_tokens: int = Column(Integer, default=0)
    max_threat_score: int = Column(Integer, default=0)
    violation_count: int = Column(Integer, default=0)
    risk_score: int = Column(Integer, default=0)
    metadata: dict = Column(JSON, default=dict)

    organization = relationship("Organization", back_populates="sessions")
    events = relationship("Event", back_populates="session", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="session")


class Event(Base):
    __tablename__ = "events"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    session_id: str = Column(String(36), ForeignKey("agent_sessions.id"), nullable=False)
    event_type: str = Column(String(50), nullable=False)
    agent_name: str = Column(String(255))
    timestamp: float = Column(Float, nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    data: dict = Column(JSON, default=dict)
    threat_score: int = Column(Integer, default=0)
    threat_reasons: list = Column(JSON, default=list)
    blocked: bool = Column(Boolean, default=False)
    latency_ms: Optional[float] = Column(Float, nullable=True)

    session = relationship("AgentSession", back_populates="events")


class Alert(Base):
    __tablename__ = "alerts"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Optional[str] = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    session_id: Optional[str] = Column(String(36), ForeignKey("agent_sessions.id"), nullable=True)
    event_id: Optional[str] = Column(String(36), nullable=True)
    title: str = Column(String(500), nullable=False)
    description: str = Column(Text, default="")
    severity: str = Column(String(20), nullable=False)  # info, warning, high, critical
    alert_type: str = Column(String(100), nullable=False)  # prompt_injection, pii_leak, etc.
    status: str = Column(String(50), default="open")  # open, acknowledged, resolved, false_positive
    threat_score: int = Column(Integer, default=0)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    updated_at: datetime = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at: Optional[datetime] = Column(DateTime, nullable=True)
    resolved_at: Optional[datetime] = Column(DateTime, nullable=True)
    acknowledged_by: Optional[str] = Column(String(255), nullable=True)
    resolved_by: Optional[str] = Column(String(255), nullable=True)
    dedup_key: Optional[str] = Column(String(255), nullable=True)  # For deduplication
    context: dict = Column(JSON, default=dict)
    notes: str = Column(Text, default="")

    organization = relationship("Organization", back_populates="alerts")
    session = relationship("AgentSession", back_populates="alerts")


class Policy(Base):
    __tablename__ = "policies"

    id: str = Column(String(36), primary_key=True, default=gen_uuid)
    organization_id: Optional[str] = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    name: str = Column(String(255), nullable=False)
    description: str = Column(Text, default="")
    is_enabled: bool = Column(Boolean, default=True)
    is_builtin: bool = Column(Boolean, default=False)
    action: str = Column(String(50), nullable=False)  # BLOCK, ALERT, LOG, RATE_LIMIT
    severity: str = Column(String(20), default="medium")
    condition: dict = Column(JSON, nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow)
    updated_at: datetime = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trigger_count: int = Column(Integer, default=0)
    last_triggered_at: Optional[datetime] = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="policies")
