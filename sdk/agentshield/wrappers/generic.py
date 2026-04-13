"""
Generic agent wrapper for AgentShield.

Wraps any agent object by intercepting common method calls.
Works with any agent that implements run(), invoke(), chat(), or __call__().
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional


class GenericWrapper:
    """
    Generic wrapper that intercepts common agent methods.

    Wraps: run(), invoke(), chat(), generate(), complete(), __call__()
    """

    def __init__(
        self,
        agent: Any,
        interceptor: Any,
        agent_name: str = "agent",
    ) -> None:
        self._agent = agent
        self._interceptor = interceptor
        self._agent_name = agent_name
        self._session_id = str(uuid.uuid4())

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.run()."""
        return self._run_with_intercept("run", *args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.invoke()."""
        return self._run_with_intercept("invoke", *args, **kwargs)

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.chat()."""
        return self._run_with_intercept("chat", *args, **kwargs)

    def generate(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.generate()."""
        return self._run_with_intercept("generate", *args, **kwargs)

    def complete(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept agent.complete()."""
        return self._run_with_intercept("complete", *args, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Intercept direct agent() calls."""
        return self._run_with_intercept("__call__", *args, **kwargs)

    def _run_with_intercept(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Run the wrapped method with full interception."""
        from ..interceptor import EventType, InterceptorEvent

        # Extract prompt from first positional arg or common kwargs
        prompt = ""
        if args:
            prompt = str(args[0])
        elif "input" in kwargs:
            prompt = str(kwargs["input"])
        elif "prompt" in kwargs:
            prompt = str(kwargs["prompt"])
        elif "message" in kwargs:
            prompt = str(kwargs["message"])
        elif "query" in kwargs:
            prompt = str(kwargs["query"])

        # Log LLM start
        self._interceptor.capture_llm_start(
            session_id=self._session_id,
            agent_name=self._agent_name,
            prompt=prompt,
            extra={"method": method_name},
        )

        # Call the actual method
        start = time.monotonic()
        method = getattr(self._agent, method_name)
        result = method(*args, **kwargs)
        latency_ms = (time.monotonic() - start) * 1000

        # Capture the output
        output = str(result) if result is not None else ""
        self._interceptor.capture_llm_end(
            session_id=self._session_id,
            agent_name=self._agent_name,
            output=output,
            latency_ms=latency_ms,
        )

        return result

    def get_session_id(self) -> str:
        """Return the session ID for this wrapped agent."""
        return self._session_id

    def kill(self) -> None:
        """Kill this agent session."""
        self._interceptor.kill_session(self._session_id)

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying agent."""
        return getattr(self._agent, name)
