"""Billing models — Plan, Subscription, UsageRecord, Invoice."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, Column, Float, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase


class BillingBase(DeclarativeBase):
    pass


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> float:
    return time.time()


class Plan(BillingBase):
    __tablename__ = "plans"
    plan_id = Column(String(36), primary_key=True, default=_uuid)
    name = Column(String(50), nullable=False, unique=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, default="")
    price_monthly_usd = Column(Float, default=0.0)
    price_yearly_usd = Column(Float, default=0.0)
    stripe_price_id_monthly = Column(String(100), nullable=True)
    stripe_price_id_yearly = Column(String(100), nullable=True)
    features = Column(JSON, default=dict)
    limits = Column(JSON, default=dict)
    active = Column(Boolean, default=True)
    created_at = Column(Float, default=_now)


class Subscription(BillingBase):
    __tablename__ = "subscriptions"
    subscription_id = Column(String(36), primary_key=True, default=_uuid)
    org_id = Column(String(36), nullable=False, index=True)
    plan_id = Column(String(36), nullable=False)
    stripe_subscription_id = Column(String(100), nullable=True)
    stripe_customer_id = Column(String(100), nullable=True)
    status = Column(String(20), default="active")
    billing_cycle = Column(String(10), default="monthly")
    current_period_start = Column(Float, default=_now)
    current_period_end = Column(Float, nullable=True)
    cancel_at_period_end = Column(Boolean, default=False)
    created_at = Column(Float, default=_now)
    updated_at = Column(Float, default=_now)


class UsageRecord(BillingBase):
    __tablename__ = "usage_records"
    record_id = Column(String(36), primary_key=True, default=_uuid)
    org_id = Column(String(36), nullable=False, index=True)
    metric = Column(String(50), nullable=False)
    value = Column(Float, default=0.0)
    period_start = Column(Float, nullable=False)
    period_end = Column(Float, nullable=True)
    recorded_at = Column(Float, default=_now)
    metadata = Column(JSON, default=dict)


class Invoice(BillingBase):
    __tablename__ = "invoices"
    invoice_id = Column(String(36), primary_key=True, default=_uuid)
    org_id = Column(String(36), nullable=False, index=True)
    stripe_invoice_id = Column(String(100), nullable=True)
    amount_due_cents = Column(Integer, default=0)
    amount_paid_cents = Column(Integer, default=0)
    currency = Column(String(3), default="usd")
    status = Column(String(20), default="draft")
    period_start = Column(Float, nullable=True)
    period_end = Column(Float, nullable=True)
    paid_at = Column(Float, nullable=True)
    due_date = Column(Float, nullable=True)
    line_items = Column(JSON, default=list)
    created_at = Column(Float, default=_now)
