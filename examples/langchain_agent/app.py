"""
Full LangChain agent with AgentShield protection.

This example shows how to protect a LangChain ReAct agent with AgentShield,
intercepting all tool calls and LLM invocations for security monitoring.
"""
from __future__ import annotations

import os
import sys

# Add SDK to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))


def create_protected_langchain_agent():
    """Create a LangChain agent with AgentShield protection."""
    try:
        from langchain.agents import AgentType, initialize_agent
        from langchain.tools import Tool
        from langchain_community.llms import OpenAI
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:
        print("Install: pip install langchain langchain-community openai")
        return None

    class AgentShieldCallback(BaseCallbackHandler):
        """LangChain callback that sends events to AgentShield."""

        def __init__(self, server_url: str, api_key: str):
            self.server_url = server_url
            self.api_key = api_key
            self.session_id = None
            self._events = []

        def on_agent_action(self, action, **kwargs):
            from urllib import request as urlreq
            import json
            event = {
                "event_type": "tool_call",
                "tool_name": action.tool,
                "tool_input": str(action.tool_input),
                "session_id": self.session_id or "unknown",
                "agent_id": "langchain-agent",
            }
            self._events.append(event)
            try:
                req = urlreq.Request(
                    f"{self.server_url}/api/events",
                    data=json.dumps(event).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "X-API-Key": self.api_key,
                    },
                    method="POST",
                )
                urlreq.urlopen(req, timeout=2)
            except Exception:
                pass  # Don't block the agent if AgentShield is unavailable

        def on_tool_end(self, output, **kwargs):
            # Check output for sensitive data
            from agentshield.testing.assertions import assert_no_pii_leaked
            try:
                assert_no_pii_leaked(str(output))
            except AssertionError as e:
                print(f"[AgentShield WARNING] PII detected in tool output: {e}")

    # Configure
    server_url = os.getenv("AGENTSHIELD_SERVER_URL", "http://localhost:8000")
    api_key = os.getenv("AGENTSHIELD_API_KEY", "test-key")

    callback = AgentShieldCallback(server_url=server_url, api_key=api_key)

    # Create tools
    tools = [
        Tool(
            name="search",
            func=lambda q: f"Search results for: {q}",
            description="Search the web for information",
        ),
        Tool(
            name="calculator",
            func=lambda x: str(eval(x)),
            description="Calculate mathematical expressions",
        ),
    ]

    # Initialize agent with callback
    llm = OpenAI(temperature=0)
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        callbacks=[callback],
        verbose=True,
    )

    return agent, callback


if __name__ == "__main__":
    print("AgentShield + LangChain Integration Example")
    print("=" * 50)

    result = create_protected_langchain_agent()
    if result is None:
        print("LangChain not installed. Install with: pip install langchain langchain-community openai")
        sys.exit(0)

    agent, callback = result
    callback.session_id = "demo-session-001"

    # This would run if OPENAI_API_KEY is set
    if os.getenv("OPENAI_API_KEY"):
        response = agent.run("What is 2 + 2?")
        print(f"Agent response: {response}")
        print(f"Events recorded: {len(callback._events)}")
    else:
        print("Set OPENAI_API_KEY to run the agent.")
        print("AgentShield protection is configured and ready.")
