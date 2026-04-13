"""
AutoGen wrapper for AgentShield.

Instruments AutoGen's ConversableAgent to intercept all messages and LLM calls.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from .generic import GenericWrapper


class AutoGenWrapper(GenericWrapper):
    """
    AutoGen wrapper that instruments agent message passing.

    Patches generate_reply() and initiate_chat() to capture all interactions.
    """

    def __init__(self, agent: Any, interceptor: Any, agent_name: str = "autogen-agent") -> None:
        super().__init__(agent=agent, interceptor=interceptor, agent_name=agent_name)
        self._patch_autogen_agent()

    def _patch_autogen_agent(self) -> None:
        """Patch AutoGen agent methods to add monitoring."""
        try:
            original_generate_reply = self._agent.__class__.generate_reply

            interceptor = self._interceptor
            session_id = self._session_id
            agent_name_ref = self._agent_name

            def patched_generate_reply(
                self_agent: Any,
                messages: Optional[list] = None,
                sender: Optional[Any] = None,
                **kwargs: Any,
            ) -> Any:
                prompt = ""
                if messages:
                    last_msg = messages[-1]
                    if isinstance(last_msg, dict):
                        prompt = last_msg.get("content", "")
                    else:
                        prompt = str(last_msg)

                interceptor.capture_llm_start(
                    session_id=session_id,
                    agent_name=agent_name_ref,
                    prompt=prompt,
                    extra={"sender": str(sender) if sender else ""},
                )

                start = time.monotonic()
                result = original_generate_reply(self_agent, messages=messages, sender=sender, **kwargs)
                latency = (time.monotonic() - start) * 1000

                output = ""
                if isinstance(result, tuple):
                    output = str(result[1]) if len(result) > 1 else str(result[0])
                elif result is not None:
                    output = str(result)

                interceptor.capture_llm_end(
                    session_id=session_id,
                    agent_name=agent_name_ref,
                    output=output,
                    latency_ms=latency,
                )
                return result

            # Patch the instance method (not the class to avoid side effects)
            import types
            self._agent.generate_reply = types.MethodType(patched_generate_reply, self._agent)
        except Exception:
            pass

    def initiate_chat(self, recipient: Any, message: Any, **kwargs: Any) -> Any:
        """Intercept AutoGen initiate_chat()."""
        from ..interceptor import InterceptorEvent, EventType
        event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.AGENT_START,
            agent_name=self._agent_name,
            data={
                "message": str(message)[:1000],
                "recipient": type(recipient).__name__,
            },
        )
        self._interceptor._dispatch(event)

        start = time.monotonic()
        result = self._agent.initiate_chat(recipient, message=message, **kwargs)
        latency = (time.monotonic() - start) * 1000

        end_event = InterceptorEvent(
            session_id=self._session_id,
            event_type=EventType.AGENT_END,
            agent_name=self._agent_name,
            latency_ms=latency,
            data={},
        )
        self._interceptor._dispatch(end_event)
        return result
