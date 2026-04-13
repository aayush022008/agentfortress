"""
FastAPI app running a protected agent with AgentShield middleware.
"""
from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Protected Agent API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AgentRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None
    agent_id: str = "default-agent"


class AgentResponse(BaseModel):
    session_id: str
    response: str
    events_recorded: int
    alerts_fired: int


AGENTSHIELD_URL = os.getenv("AGENTSHIELD_SERVER_URL", "http://localhost:8000")
AGENTSHIELD_KEY = os.getenv("AGENTSHIELD_API_KEY", "test-key")


def send_agentshield_event(event: Dict[str, Any]) -> bool:
    """Send event to AgentShield server."""
    from urllib import request as urlreq, error
    try:
        req = urlreq.Request(
            f"{AGENTSHIELD_URL}/api/events",
            data=json.dumps(event).encode(),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": AGENTSHIELD_KEY,
            },
            method="POST",
        )
        with urlreq.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


@app.middleware("http")
async def agentshield_request_middleware(request: Request, call_next):
    """Middleware that scans requests for malicious content."""
    if request.method == "POST" and "/run" in str(request.url):
        try:
            body = await request.body()
            data = json.loads(body)
            prompt = data.get("prompt", "")

            # Import here to avoid startup delay
            import sys
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))
            from agentshield.ml.nlp_classifier import NLPClassifier

            clf = NLPClassifier()
            result = clf.classify(prompt)

            if result.is_malicious and result.confidence > 0.9:
                send_agentshield_event({
                    "event_type": "alert",
                    "alert_type": "prompt_injection",
                    "severity": "critical",
                    "description": f"Prompt injection blocked at API gateway",
                    "agent_id": data.get("agent_id", "unknown"),
                })
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=400,
                    content={"error": "Request blocked by security policy"},
                )

            # Recreate request with body for downstream
            from starlette.requests import Request as StarletteRequest
        except Exception:
            pass  # Don't block on errors

    return await call_next(request)


@app.post("/run", response_model=AgentResponse)
async def run_agent(req: AgentRequest) -> AgentResponse:
    """Run a protected agent with AgentShield monitoring."""
    session_id = req.session_id or str(uuid.uuid4())
    events_recorded = 0
    alerts_fired = 0

    # Record session start
    if send_agentshield_event({
        "event_type": "session_start",
        "agent_id": req.agent_id,
        "session_id": session_id,
        "prompt": req.prompt[:500],
    }):
        events_recorded += 1

    # Simulate agent execution (replace with real agent)
    response = f"[Protected Agent] Processed: {req.prompt[:100]}"

    # Record session end
    if send_agentshield_event({
        "event_type": "session_end",
        "agent_id": req.agent_id,
        "session_id": session_id,
        "response": response[:500],
    }):
        events_recorded += 1

    return AgentResponse(
        session_id=session_id,
        response=response,
        events_recorded=events_recorded,
        alerts_fired=alerts_fired,
    )


@app.get("/health")
async def health():
    return {"status": "healthy", "agentshield_url": AGENTSHIELD_URL}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
