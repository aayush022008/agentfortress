"""
LangChain integration wrapper for AgentShield.

Implements LangChain's BaseCallbackHandler to intercept all LangChain events.
Supports chains, agents, and tools.
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Optional, Union

from .generic import GenericWrapper


class LangChainShieldCallback:
    """
    LangChain callback handler that sends events to AgentShield.

    Usage:
        from langchain.agents import AgentExecutor
        from agentshield.wrappers.langchain import LangChainShieldCallback

        callback = LangChainShieldCallback(interceptor=interceptor, session_id="abc")
        agent.run("task", callbacks=[callback])
    """

    def __init__(self, interceptor: Any, session_id: str, agent_name: str = "langchain-agent") -> None:
        self._interceptor = interceptor
        self._session_id = session_id
        self._agent_name = agent_name
        self._llm_start_times: dict[str, float] = {}
        self._tool_start_times: dict[str, float] = {}

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Called when LLM starts running."""
        run_id = str(kwargs.get("run_id", uuid.uuid4()))
        self._llm_start_times[run_id] = time.monotonic()
        model_name = serialized.get("name", serialized.get("id", ["unknown"])[-1])
        prompt = " ".join(prompts)
        self._interceptor.capture_llm_start(
            session_id=self._session_id,
            agent_name=self._agent_name,
            prompt=prompt,
            model=model_name,
        )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when LLM ends running."""
        run_id = str(kwargs.get("run_id", ""))
        start = self._llm_start_times.pop(run_id, None)
        latency_ms = (time.monotonic() - start) * 1000 if start else None

        output = ""
        input_tokens = 0
        output_tokens = 0

        try:
            generations = response.generations
            if generations:
                output = generations[0][0].text
            if hasattr(response, "llm_output") and response.llm_output:
                usage = response.llm_output.get("token_usage", {})
                input_tokens = usage.get("prompt_tokens", 0)
                output_tokens = usage.get("completion_tokens", 0)
        except (AttributeError, IndexError):
            pass

        self._interceptor.capture_llm_end(
            session_id=self._session_id,
            agent_name=self._agent_name,
            output=output,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )

    def on_llm_error(self, error: Union[Exception, KeyboardInterrupt], **kwargs: Any) -> None:
        """Called when LLM errors."""
        from ..interceptor import InterceptorEvent, EventType
        event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.LLM_ERROR,
            agent_name=self._agent_name,
            data={"error": str(error)},
        )
        self._interceptor._dispatch(event)

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running."""
        run_id = str(kwargs.get("run_id", uuid.uuid4()))
        self._tool_start_times[run_id] = time.monotonic()
        tool_name = serialized.get("name", "unknown_tool")
        self._interceptor.capture_tool_start(
            session_id=self._session_id,
            agent_name=self._agent_name,
            tool_name=tool_name,
            tool_args={"input": input_str},
        )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool ends running."""
        run_id = str(kwargs.get("run_id", ""))
        start = self._tool_start_times.pop(run_id, None)
        latency_ms = (time.monotonic() - start) * 1000 if start else None
        tool_name = kwargs.get("name", "unknown_tool")
        self._interceptor.capture_tool_end(
            session_id=self._session_id,
            agent_name=self._agent_name,
            tool_name=tool_name,
            tool_result=output,
            latency_ms=latency_ms,
        )

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        from ..interceptor import InterceptorEvent, EventType
        event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.TOOL_ERROR,
            agent_name=self._agent_name,
            data={"error": str(error)},
        )
        self._interceptor._dispatch(event)

    def on_chain_start(self, serialized: dict, inputs: dict, **kwargs: Any) -> None:
        """Called when a chain starts."""
        pass

    def on_chain_end(self, outputs: dict, **kwargs: Any) -> None:
        """Called when a chain ends."""
        pass

    def on_chain_error(self, error: Any, **kwargs: Any) -> None:
        """Called when a chain errors."""
        pass

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        """Called when agent takes an action."""
        pass

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        """Called when agent finishes."""
        pass


class LangChainWrapper(GenericWrapper):
    """
    LangChain agent wrapper that attaches the AgentShield callback.

    Automatically injects the callback into the agent if it has a 'callbacks' attribute.
    Falls back to generic method interception otherwise.
    """

    def __init__(self, agent: Any, interceptor: Any, agent_name: str = "langchain-agent") -> None:
        super().__init__(agent=agent, interceptor=interceptor, agent_name=agent_name)
        self._callback = LangChainShieldCallback(
            interceptor=interceptor,
            session_id=self._session_id,
            agent_name=agent_name,
        )
        # Inject callback if agent supports it
        if hasattr(agent, "callbacks"):
            if agent.callbacks is None:
                agent.callbacks = [self._callback]
            elif isinstance(agent.callbacks, list):
                agent.callbacks.append(self._callback)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run with LangChain callback injection."""
        # Ensure our callback is in kwargs callbacks
        if "callbacks" not in kwargs:
            kwargs["callbacks"] = [self._callback]
        elif isinstance(kwargs["callbacks"], list):
            if self._callback not in kwargs["callbacks"]:
                kwargs["callbacks"].append(self._callback)

        return self._agent.run(*args, **kwargs)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Invoke with callback injection."""
        if "config" in kwargs:
            config = kwargs["config"]
            if isinstance(config, dict) and "callbacks" not in config:
                config["callbacks"] = [self._callback]
        return self._agent.invoke(*args, **kwargs)
