"""Tests for AgentShield server API."""

import pytest
import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../server"))

pytest_plugins = ('pytest_asyncio',)


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def client():
    """Create test client for the FastAPI app."""
    from httpx import AsyncClient, ASGITransport
    from main import app
    from database.connection import init_db

    # Use in-memory SQLite for tests
    import os
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health_endpoint(client):
    """Health endpoint should return 200."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_ingest_single_event(client):
    """Should accept a single event."""
    import time
    resp = await client.post(
        "/api/events/",
        json={
            "session_id": "test-session-1",
            "event_type": "llm_start",
            "agent_name": "test-agent",
            "timestamp": time.time(),
            "data": {"prompt": "Hello world"},
            "threat_score": 0,
            "threat_reasons": [],
            "blocked": False,
        },
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 201


@pytest.mark.asyncio
async def test_ingest_batch_events(client):
    """Should accept batch events."""
    import time
    events = [
        {
            "session_id": "batch-session",
            "event_type": "llm_start",
            "agent_name": "agent",
            "timestamp": time.time(),
            "data": {},
            "threat_score": 0,
            "threat_reasons": [],
            "blocked": False,
        }
        for _ in range(3)
    ]
    resp = await client.post(
        "/api/events/batch",
        json={"events": events},
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 200
    assert resp.json()["processed"] == 3


@pytest.mark.asyncio
async def test_list_sessions_empty(client):
    """Should return empty list initially."""
    resp = await client.get("/api/sessions/", headers={"X-API-Key": "admin-secret-change-me"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_alerts_empty(client):
    """Should return empty list initially."""
    resp = await client.get("/api/alerts/", headers={"X-API-Key": "admin-secret-change-me"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_create_policy(client):
    """Should create a new policy."""
    resp = await client.post(
        "/api/policies/",
        json={
            "name": "Test Policy",
            "action": "ALERT",
            "severity": "medium",
            "condition": {"type": "threat_score_above", "threshold": 50},
        },
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Policy"
    assert data["action"] == "ALERT"


@pytest.mark.asyncio
async def test_analytics_overview(client):
    """Analytics overview should return stats."""
    resp = await client.get("/api/analytics/overview", headers={"X-API-Key": "admin-secret-change-me"})
    assert resp.status_code == 200
    data = resp.json()
    assert "total_sessions" in data
    assert "open_alerts" in data


@pytest.mark.asyncio
async def test_create_organization(client):
    """Should create an organization."""
    resp = await client.post(
        "/api/organizations/",
        json={"name": "Test Org"},
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Test Org"
    assert "slug" in data


@pytest.mark.asyncio
async def test_create_api_key(client):
    """Should create an API key and return the raw key."""
    resp = await client.post(
        "/api/apikeys/",
        json={"name": "Test Key"},
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "key" in data
    assert data["key"].startswith("as_")


@pytest.mark.asyncio
async def test_session_not_found(client):
    """Non-existent session should return 404."""
    resp = await client.get(
        "/api/sessions/nonexistent-id",
        headers={"X-API-Key": "admin-secret-change-me"},
    )
    assert resp.status_code == 404
