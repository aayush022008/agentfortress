"""
OpenAI Agents SDK wrapper for AgentShield.

Instruments the OpenAI Agents SDK Runner to capture all agent events.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from .generic import GenericWrapper


class OpenAIAgentsWrapper(GenericWrapper):
    """
    OpenAI Agents SDK wrapper.

    Instruments Runner.run() and Runner.run_streamed() to capture all events.
    Also supports wrapping individual Agent objects.
    """

    def __init__(self, agent: Any, interceptor: Any, agent_name: str = "openai-agent") -> None:
        super().__init__(agent=agent, interceptor=interceptor, agent_name=agent_name)

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept async Runner.run()."""
        from ..interceptor import InterceptorEvent, EventType

        # Extract input
        input_data = args[0] if args else kwargs.get("input", "")
        prompt = str(input_data) if not isinstance(input_data, str) else input_data

        self._interceptor.capture_llm_start(
            session_id=self._session_id,
            agent_name=self._agent_name,
            prompt=prompt,
        )

        start = time.monotonic()
        try:
            result = await self._agent.run(*args, **kwargs)
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

        # Extract output
        output = ""
        if hasattr(result, "final_output"):
            output = str(result.final_output)
        elif hasattr(result, "output"):
            output = str(result.output)
        else:
            output = str(result)

        self._interceptor.capture_llm_end(
            session_id=self._session_id,
            agent_name=self._agent_name,
            output=output,
            latency_ms=latency,
        )
        return result

    def run_sync(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous version of run."""
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, self.run(*args, **kwargs))
                return future.result()
        else:
            return loop.run_until_complete(self.run(*args, **kwargs))
