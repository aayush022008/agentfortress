"""
OpenTelemetry integration — export AgentShield traces and spans.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional


class OpenTelemetryIntegration:
    """
    Exports AgentShield session events as OpenTelemetry traces and spans.

    Requires: opentelemetry-api, opentelemetry-sdk, opentelemetry-exporter-otlp

    Usage::

        otel = OpenTelemetryIntegration(
            service_name="agentshield",
            otlp_endpoint="http://collector.local:4317",
        )
        otel.setup()
        with otel.trace_session(session_id="sess-001", agent_id="agent-001") as span:
            span.set_attribute("event.count", 42)
    """

    def __init__(
        self,
        service_name: str = "agentshield",
        otlp_endpoint: Optional[str] = None,
        insecure: bool = True,
    ) -> None:
        self.service_name = service_name
        self.otlp_endpoint = otlp_endpoint
        self.insecure = insecure
        self._tracer = None
        self._meter = None

    def setup(self) -> bool:
        """Initialize OTel providers. Returns True if successful."""
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.sdk.resources import Resource

            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)

            if self.otlp_endpoint:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter(
                    endpoint=self.otlp_endpoint,
                    insecure=self.insecure,
                )
                provider.add_span_processor(BatchSpanProcessor(exporter))

            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(self.service_name)
            return True
        except ImportError:
            return False

    def trace_session(self, session_id: str, agent_id: str) -> Any:
        """Return a context manager for tracing an agent session."""
        if not self._tracer:
            return _NoopSpan()

        return self._tracer.start_as_current_span(
            f"agent.session",
            attributes={
                "session.id": session_id,
                "agent.id": agent_id,
                "service.name": self.service_name,
            },
        )

    def record_event(self, span: Any, event: Dict[str, Any]) -> None:
        """Record an agent event on an active span."""
        if span is None or isinstance(span, _NoopSpan):
            return
        try:
            attrs = {
                "event.type": str(event.get("event_type", "unknown")),
                "event.agent_id": str(event.get("agent_id", "")),
            }
            if "tool_name" in event:
                attrs["tool.name"] = str(event["tool_name"])
            span.add_event(
                name=str(event.get("event_type", "event")),
                attributes=attrs,
            )
        except Exception:
            pass

    def record_alert(self, span: Any, alert: Dict[str, Any]) -> None:
        """Record an alert as a span event with severity."""
        if span is None or isinstance(span, _NoopSpan):
            return
        try:
            span.add_event(
                name="agentshield.alert",
                attributes={
                    "alert.type": str(alert.get("alert_type", "")),
                    "alert.severity": str(alert.get("severity", "")),
                    "alert.description": str(alert.get("description", ""))[:200],
                },
            )
        except Exception:
            pass

    def send_metric(
        self,
        name: str,
        value: float,
        attributes: Optional[Dict[str, str]] = None,
    ) -> None:
        """Record a metric via OTel Metrics API."""
        if not self._meter:
            return
        try:
            counter = self._meter.create_counter(name)
            counter.add(int(value), attributes=attributes or {})
        except Exception:
            pass


class _NoopSpan:
    """No-op span context manager when OTel is not configured."""

    def __enter__(self) -> "_NoopSpan":
        return self

    def __exit__(self, *_: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def add_event(self, name: str, **kwargs: Any) -> None:
        pass
