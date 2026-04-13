"""
CrewAI wrapper for AgentShield.

Patches CrewAI's task execution to intercept LLM and tool calls.
"""

from __future__ import annotations

import time
from typing import Any

from .generic import GenericWrapper


class CrewAIWrapper(GenericWrapper):
    """
    CrewAI wrapper that instruments crew execution.

    Intercepts Crew.kickoff() and monitors all agent tasks and tool calls.
    """

    def __init__(self, agent: Any, interceptor: Any, agent_name: str = "crewai-crew") -> None:
        super().__init__(agent=agent, interceptor=interceptor, agent_name=agent_name)
        self._patch_crew()

    def _patch_crew(self) -> None:
        """Patch the crew's agents to add AgentShield monitoring."""
        try:
            # Try to patch individual agents in the crew
            agents = getattr(self._agent, "agents", []) or []
            for crew_agent in agents:
                self._patch_agent_llm(crew_agent)
        except Exception:
            pass

    def _patch_agent_llm(self, crew_agent: Any) -> None:
        """Patch an individual CrewAI agent's LLM calls."""
        try:
            llm = getattr(crew_agent, "llm", None)
            if llm is None:
                return

            original_call = llm.__class__.__call__
            interceptor = self._interceptor
            session_id = self._session_id
            agent_name = getattr(crew_agent, "role", self._agent_name)

            def patched_call(self_llm: Any, prompt: Any, *args: Any, **kwargs: Any) -> Any:
                interceptor.capture_llm_start(
                    session_id=session_id,
                    agent_name=agent_name,
                    prompt=str(prompt),
                )
                start = time.monotonic()
                result = original_call(self_llm, prompt, *args, **kwargs)
                latency = (time.monotonic() - start) * 1000
                interceptor.capture_llm_end(
                    session_id=session_id,
                    agent_name=agent_name,
                    output=str(result),
                    latency_ms=latency,
                )
                return result

            llm.__class__.__call__ = patched_call
        except Exception:
            pass

    def kickoff(self, inputs: Any = None) -> Any:
        """Intercept CrewAI Crew.kickoff()."""
        from ..interceptor import InterceptorEvent, EventType
        event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.AGENT_START,
            agent_name=self._agent_name,
            data={"inputs": str(inputs)[:500] if inputs else ""},
        )
        self._interceptor._dispatch(event)

        start = time.monotonic()
        try:
            if inputs is not None:
                result = self._agent.kickoff(inputs=inputs)
            else:
                result = self._agent.kickoff()
        except Exception as e:
            error_event = InterceptorEvent(
                session_id=self._session_id,
                event_type=EventType.AGENT_ERROR,
                agent_name=self._agent_name,
                data={"error": str(e)},
            )
            self._interceptor._dispatch(error_event)
            raise

        latency = (time.monotonic() - start) * 1000
        end_event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.AGENT_END,
            agent_name=self._agent_name,
            latency_ms=latency,
            data={"result_preview": str(result)[:500]},
        )
        self._interceptor._dispatch(end_event)
        return result
