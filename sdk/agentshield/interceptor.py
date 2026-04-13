"""
AgentShield Interceptor — the core event capture and analysis engine.

Intercepts LLM calls, tool calls, and memory operations. Runs threat analysis
on every captured event and dispatches to policy engine and transport.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    LLM_START = "llm_start"
    LLM_END = "llm_end"
    LLM_ERROR = "llm_error"
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    TOOL_ERROR = "tool_error"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    AGENT_START = "agent_start"
    AGENT_END = "agent_end"
    AGENT_ERROR = "agent_error"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    KILL_SWITCH = "kill_switch"


@dataclass
class InterceptorEvent:
    """
    A captured event from an agent's execution.

    Attributes:
        event_id: Unique identifier for this event
        session_id: The agent session this belongs to
        event_type: Type of event
        agent_name: Name of the agent
        timestamp: Unix timestamp when event was captured
        data: Event-specific data payload
        threat_score: 0-100 threat score (0 = safe)
        threat_reasons: List of reasons if threat detected
        blocked: Whether this event was blocked by policy
        latency_ms: For LLM/tool calls, execution time
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""
    event_type: EventType = EventType.LLM_START
    agent_name: str = ""
    timestamp: float = field(default_factory=time.time)
    data: dict[str, Any] = field(default_factory=dict)
    threat_score: int = 0
    threat_reasons: list[str] = field(default_factory=list)
    blocked: bool = False
    latency_ms: Optional[float] = None


class AgentKilledException(Exception):
    """Raised when the kill switch is activated for an agent session."""
    pass


class PolicyBlockException(Exception):
    """Raised when a policy blocks an agent action."""

    def __init__(self, message: str, event: InterceptorEvent) -> None:
        super().__init__(message)
        self.event = event


class Interceptor:
    """
    Core event interceptor for AgentShield.

    Captures, analyzes, and dispatches events from AI agent execution.
    Integrates with the policy engine to enforce security policies.
    """

    def __init__(
        self,
        config: Any,
        policy_engine: Any,
        transport: Any,
        audit_logger: Any,
    ) -> None:
        self._config = config
        self._policy_engine = policy_engine
        self._transport = transport
        self._audit_logger = audit_logger
        self._killed_sessions: set[str] = set()
        self._session_stats: dict[str, dict] = {}

    def _get_session_stats(self, session_id: str) -> dict:
        if session_id not in self._session_stats:
            self._session_stats[session_id] = {
                "llm_calls": 0,
                "tool_calls": 0,
                "violations": 0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "start_time": time.time(),
            }
        return self._session_stats[session_id]

    def _check_killed(self, session_id: str) -> None:
        if session_id in self._killed_sessions:
            raise AgentKilledException(
                f"Agent session {session_id} has been killed by kill switch"
            )

    def capture_llm_start(
        self,
        session_id: str,
        agent_name: str,
        prompt: str,
        model: str = "",
        temperature: float = 0.7,
        extra: Optional[dict] = None,
    ) -> InterceptorEvent:
        """
        Capture the start of an LLM call and analyze the prompt.

        Raises:
            AgentKilledException: If session has been killed
            PolicyBlockException: If policy blocks this call
        """
        self._check_killed(session_id)

        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.LLM_START,
            agent_name=agent_name,
            data={
                "prompt": prompt[:5000],  # truncate for storage
                "model": model,
                "temperature": temperature,
                **(extra or {}),
            },
        )

        # Analyze prompt for injection
        if self._config.enable_prompt_injection:
            threat_score, reasons = self._analyze_prompt(prompt)
            event.threat_score = threat_score
            event.threat_reasons = reasons

        # Enforce policies
        action = self._policy_engine.evaluate(event)
        if action == "BLOCK":
            event.blocked = True
            self._dispatch(event)
            raise PolicyBlockException(
                f"Prompt blocked by policy: {event.threat_reasons}",
                event=event,
            )

        stats = self._get_session_stats(session_id)
        stats["llm_calls"] += 1

        self._dispatch(event)
        return event

    def capture_llm_end(
        self,
        session_id: str,
        agent_name: str,
        output: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model: str = "",
        latency_ms: Optional[float] = None,
    ) -> InterceptorEvent:
        """
        Capture the end of an LLM call and analyze the output.

        Raises:
            PolicyBlockException: If policy blocks this output
        """
        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.LLM_END,
            agent_name=agent_name,
            latency_ms=latency_ms,
            data={
                "output": output[:5000],
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "model": model,
                "output_size_bytes": len(output.encode()),
            },
        )

        # Analyze output for PII and exfil
        if self._config.enable_pii_detection:
            threat_score, reasons = self._analyze_output(output)
            event.threat_score = threat_score
            event.threat_reasons = reasons

        action = self._policy_engine.evaluate(event)
        if action == "BLOCK":
            event.blocked = True
            self._dispatch(event)
            raise PolicyBlockException(
                f"LLM output blocked by policy: {event.threat_reasons}",
                event=event,
            )

        stats = self._get_session_stats(session_id)
        stats["total_input_tokens"] += input_tokens
        stats["total_output_tokens"] += output_tokens

        self._dispatch(event)
        return event

    def capture_tool_start(
        self,
        session_id: str,
        agent_name: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> InterceptorEvent:
        """
        Capture the start of a tool call.

        Raises:
            AgentKilledException: If session has been killed
            PolicyBlockException: If policy blocks this tool call
        """
        self._check_killed(session_id)

        # Check tool whitelist
        if (
            self._config.allowed_tools
            and tool_name not in self._config.allowed_tools
        ):
            event = InterceptorEvent(
                session_id=session_id,
                event_type=EventType.TOOL_START,
                agent_name=agent_name,
                data={"tool_name": tool_name, "tool_args": str(tool_args)[:2000]},
                threat_score=80,
                threat_reasons=[f"Tool '{tool_name}' not in allowed tools list (scope creep)"],
                blocked=True,
            )
            self._dispatch(event)
            raise PolicyBlockException(
                f"Tool '{tool_name}' not in allowed tools whitelist",
                event=event,
            )

        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.TOOL_START,
            agent_name=agent_name,
            data={
                "tool_name": tool_name,
                "tool_args": str(tool_args)[:2000],
            },
        )

        # Check for dangerous tool patterns in args
        args_str = str(tool_args)
        threat_score, reasons = self._analyze_prompt(args_str)
        event.threat_score = threat_score
        event.threat_reasons = reasons

        action = self._policy_engine.evaluate(event)
        if action == "BLOCK":
            event.blocked = True
            self._dispatch(event)
            raise PolicyBlockException(
                f"Tool call blocked by policy: {event.threat_reasons}",
                event=event,
            )

        stats = self._get_session_stats(session_id)
        stats["tool_calls"] += 1

        self._dispatch(event)
        return event

    def capture_tool_end(
        self,
        session_id: str,
        agent_name: str,
        tool_name: str,
        tool_result: Any,
        latency_ms: Optional[float] = None,
    ) -> InterceptorEvent:
        """Capture the end of a tool call and analyze the result."""
        result_str = str(tool_result)
        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.TOOL_END,
            agent_name=agent_name,
            latency_ms=latency_ms,
            data={
                "tool_name": tool_name,
                "tool_result": result_str[:5000],
                "result_size_bytes": len(result_str.encode()),
            },
        )

        # Analyze tool result for exfil and PII
        if self._config.enable_pii_detection:
            threat_score, reasons = self._analyze_output(
                result_str,
                behavioral_signals={"output_size_bytes": len(result_str.encode())},
            )
            event.threat_score = threat_score
            event.threat_reasons = reasons

        self._dispatch(event)
        return event

    def capture_memory_read(
        self,
        session_id: str,
        agent_name: str,
        key: str,
        value: Any,
    ) -> InterceptorEvent:
        """Capture a memory read operation."""
        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.MEMORY_READ,
            agent_name=agent_name,
            data={"key": key, "value_preview": str(value)[:500]},
        )
        self._dispatch(event)
        return event

    def capture_memory_write(
        self,
        session_id: str,
        agent_name: str,
        key: str,
        value: Any,
    ) -> InterceptorEvent:
        """Capture a memory write operation."""
        value_str = str(value)
        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.MEMORY_WRITE,
            agent_name=agent_name,
            data={"key": key, "value_preview": value_str[:500]},
        )

        # Check for PII in memory writes
        if self._config.enable_pii_detection:
            threat_score, reasons = self._analyze_output(value_str)
            event.threat_score = threat_score
            event.threat_reasons = reasons

        self._dispatch(event)
        return event

    def kill_session(self, session_id: str) -> None:
        """Mark a session as killed. All subsequent calls will raise AgentKilledException."""
        self._killed_sessions.add(session_id)
        event = InterceptorEvent(
            session_id=session_id,
            event_type=EventType.KILL_SWITCH,
            agent_name="system",
            data={"reason": "Kill switch activated"},
            threat_score=100,
            threat_reasons=["Session terminated by kill switch"],
        )
        self._dispatch(event)

    def _analyze_prompt(self, text: str) -> tuple[int, list[str]]:
        """Analyze prompt text for injection and jailbreak patterns."""
        try:
            import sys
            import os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
            from threat_intel.engine.matcher import get_matcher, PatternType
            from threat_intel.engine.scorer import get_scorer

            matcher = get_matcher()
            result = matcher.match(text, [PatternType.PROMPT_INJECTION, PatternType.JAILBREAK])
            scorer = get_scorer()
            threat = scorer.score_match_result(result)
            return threat.score, threat.reasons
        except ImportError:
            # Fallback: simple heuristic
            score = 0
            reasons = []
            lower = text.lower()
            if "ignore previous instructions" in lower:
                score = 90
                reasons.append("Classic prompt injection detected")
            elif "dan mode" in lower or "jailbreak" in lower:
                score = 85
                reasons.append("Jailbreak attempt detected")
            return score, reasons

    def _analyze_output(
        self,
        text: str,
        behavioral_signals: Optional[dict] = None,
    ) -> tuple[int, list[str]]:
        """Analyze output text for PII and exfiltration patterns."""
        try:
            import sys, os
            sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../.."))
            from threat_intel.engine.matcher import get_matcher, PatternType
            from threat_intel.engine.scorer import get_scorer

            matcher = get_matcher()
            result = matcher.match(text, [PatternType.PII, PatternType.DATA_EXFIL])
            scorer = get_scorer()
            threat = scorer.score_match_result(result)
            return threat.score, threat.reasons
        except ImportError:
            import re
            score = 0
            reasons = []
            # Basic PII checks
            if re.search(r'\b\d{3}-\d{2}-\d{4}\b', text):
                score = 80
                reasons.append("Possible SSN detected in output")
            if re.search(r'sk-[A-Za-z0-9]{48}', text):
                score = 95
                reasons.append("OpenAI API key detected in output")
            return score, reasons

    def _dispatch(self, event: InterceptorEvent) -> None:
        """Dispatch event to audit logger and transport."""
        # Audit log
        if self._audit_logger:
            self._audit_logger.log(event)

        # Transport to server
        if self._transport:
            self._transport.send(event)

        # Log violations
        if event.threat_score >= 50:
            logger.warning(
                f"THREAT DETECTED | session={event.session_id} "
                f"| type={event.event_type.value} "
                f"| score={event.threat_score} "
                f"| reasons={event.threat_reasons}"
            )

    def wrap_function(
        self,
        func: Callable,
        session_id: str,
        agent_name: str,
        event_type: str = "generic",
    ) -> Callable:
        """
        Wrap a function to capture its call as an interceptor event.

        Args:
            func: The function to wrap
            session_id: Session ID to associate with events
            agent_name: Agent name to associate with events
            event_type: Event type label for this function

        Returns:
            Wrapped function with identical signature
        """

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            self._check_killed(session_id)
            start = time.monotonic()
            try:
                result = func(*args, **kwargs)
                latency = (time.monotonic() - start) * 1000
                event = InterceptorEvent(
                    session_id=session_id,
                    event_type=EventType.TOOL_END,
                    agent_name=agent_name,
                    latency_ms=latency,
                    data={"function": func.__name__, "event_type": event_type},
                )
                self._dispatch(event)
                return result
            except Exception as e:
                event = InterceptorEvent(
                    session_id=session_id,
                    event_type=EventType.TOOL_ERROR,
                    agent_name=agent_name,
                    data={"function": func.__name__, "error": str(e)},
                )
                self._dispatch(event)
                raise

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            self._check_killed(session_id)
            start = time.monotonic()
            try:
                result = await func(*args, **kwargs)
                latency = (time.monotonic() - start) * 1000
                event = InterceptorEvent(
                    session_id=session_id,
                    event_type=EventType.TOOL_END,
                    agent_name=agent_name,
                    latency_ms=latency,
                    data={"function": func.__name__, "event_type": event_type},
                )
                self._dispatch(event)
                return result
            except Exception as e:
                event = InterceptorEvent(
                    session_id=session_id,
                    event_type=EventType.TOOL_ERROR,
                    agent_name=agent_name,
                    data={"function": func.__name__, "error": str(e)},
                )
                self._dispatch(event)
                raise

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
