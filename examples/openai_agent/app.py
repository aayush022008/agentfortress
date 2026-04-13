"""
OpenAI Agents SDK example with AgentShield protection.
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))


async def run_protected_openai_agent():
    """Run an OpenAI agent with AgentShield protection."""
    try:
        from openai import AsyncOpenAI
    except ImportError:
        print("Install: pip install openai")
        return

    client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY", "sk-test"))
    agentshield_url = os.getenv("AGENTSHIELD_SERVER_URL", "http://localhost:8000")
    agentshield_key = os.getenv("AGENTSHIELD_API_KEY", "test-key")

    import json
    from urllib import request as urlreq

    session_id = f"openai-session-{os.urandom(4).hex()}"

    def send_event(event_type: str, data: dict):
        """Send an event to AgentShield."""
        event = {
            "event_type": event_type,
            "agent_id": "openai-agent-001",
            "session_id": session_id,
            **data,
        }
        try:
            req = urlreq.Request(
                f"{agentshield_url}/api/events",
                data=json.dumps(event).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": agentshield_key,
                },
                method="POST",
            )
            urlreq.urlopen(req, timeout=2)
        except Exception:
            pass

    # Define tools
    tools = [
        {
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get the current weather for a city",
                "parameters": {
                    "type": "object",
                    "properties": {"city": {"type": "string", "description": "City name"}},
                    "required": ["city"],
                },
            },
        }
    ]

    def get_weather(city: str) -> str:
        return f"Weather in {city}: 22°C, partly cloudy"

    messages = [{"role": "user", "content": "What's the weather in San Francisco?"}]

    # Scan user message for injection
    from agentshield.ml.nlp_classifier import NLPClassifier
    clf = NLPClassifier()
    for msg in messages:
        if msg["role"] == "user":
            result = clf.classify(msg["content"])
            if result.is_malicious:
                print(f"[AgentShield BLOCKED] Malicious prompt detected!")
                send_event("alert", {
                    "alert_type": "prompt_injection",
                    "severity": "critical",
                    "message": msg["content"][:200],
                })
                return

    send_event("session_start", {"messages": messages})

    # Run agent loop
    max_iterations = 5
    for i in range(max_iterations):
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )

        choice = response.choices[0]
        messages.append(choice.message.model_dump())

        if choice.finish_reason == "tool_calls":
            for tool_call in choice.message.tool_calls:
                args = json.loads(tool_call.function.arguments)
                send_event("tool_call", {
                    "tool_name": tool_call.function.name,
                    "tool_input": args,
                })
                result = get_weather(**args)
                send_event("tool_result", {
                    "tool_name": tool_call.function.name,
                    "result": result,
                })
                messages.append({
                    "role": "tool",
                    "content": result,
                    "tool_call_id": tool_call.id,
                })
        else:
            print(f"Agent: {choice.message.content}")
            send_event("session_end", {"response": choice.message.content})
            break


if __name__ == "__main__":
    print("AgentShield + OpenAI Agent Example")
    print("=" * 50)
    if not os.getenv("OPENAI_API_KEY"):
        print("Set OPENAI_API_KEY to run. Showing structure only.")
    else:
        asyncio.run(run_protected_openai_agent())
