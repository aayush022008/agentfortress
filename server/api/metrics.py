"""Prometheus metrics endpoint."""
from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

router = APIRouter(prefix="/metrics", tags=["metrics"])

_START_TIME = time.time()


@router.get("", response_class=PlainTextResponse)
async def prometheus_metrics() -> str:
    """
    Expose Prometheus metrics for AgentShield.
    If prometheus_client is installed, uses real counters/gauges.
    Otherwise returns a static sample.
    """
    try:
        from prometheus_client import (
            CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest,
            REGISTRY,
        )
        return generate_latest(REGISTRY).decode("utf-8")
    except ImportError:
        pass

    # Fallback: static sample metrics
    uptime = time.time() - _START_TIME
    return f"""# HELP agentshield_uptime_seconds Uptime in seconds
# TYPE agentshield_uptime_seconds gauge
agentshield_uptime_seconds {uptime:.1f}

# HELP agentshield_events_total Total events processed
# TYPE agentshield_events_total counter
agentshield_events_total{{status="processed"}} 0

# HELP agentshield_alerts_total Total alerts generated
# TYPE agentshield_alerts_total counter
agentshield_alerts_total{{severity="critical"}} 0
agentshield_alerts_total{{severity="high"}} 0
agentshield_alerts_total{{severity="medium"}} 0
agentshield_alerts_total{{severity="low"}} 0

# HELP agentshield_active_sessions Active agent sessions
# TYPE agentshield_active_sessions gauge
agentshield_active_sessions 0

# HELP agentshield_api_requests_total Total API requests
# TYPE agentshield_api_requests_total counter
agentshield_api_requests_total{{method="GET",status="200"}} 0
agentshield_api_requests_total{{method="POST",status="200"}} 0

# HELP agentshield_api_latency_seconds API request latency
# TYPE agentshield_api_latency_seconds histogram
agentshield_api_latency_seconds_bucket{{le="0.01"}} 0
agentshield_api_latency_seconds_bucket{{le="0.1"}} 0
agentshield_api_latency_seconds_bucket{{le="1.0"}} 0
agentshield_api_latency_seconds_bucket{{le="+Inf"}} 0
agentshield_api_latency_seconds_count 0
agentshield_api_latency_seconds_sum 0.0

# HELP agentshield_ml_scores_total ML anomaly detections
# TYPE agentshield_ml_scores_total counter
agentshield_ml_scores_total{{result="normal"}} 0
agentshield_ml_scores_total{{result="anomalous"}} 0
"""
