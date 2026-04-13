"""
Configuration management for AgentShield Server.
"""

from __future__ import annotations

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Server configuration loaded from environment variables.

    All settings can be overridden via environment variables or a .env file.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./agentshield.db"
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Security
    secret_key: str = "change-me-in-production-use-long-random-string"
    api_key_header: str = "X-API-Key"
    admin_api_key: str = "admin-secret-change-me"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Notifications
    slack_webhook_url: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    notification_email_from: Optional[str] = None

    # Redis (for pub/sub and rate limiting)
    redis_url: Optional[str] = None

    # Threat detection
    auto_block_critical: bool = True
    threat_score_alert_threshold: int = 50
    threat_score_block_threshold: int = 75

    # Event retention
    event_retention_days: int = 90
    max_events_per_session: int = 10000


settings = Settings()
