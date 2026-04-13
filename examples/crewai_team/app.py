"""
CrewAI multi-agent team with AgentShield protection.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))


def create_protected_crew():
    """Create a protected CrewAI team."""
    try:
        from crewai import Agent, Crew, Process, Task
        from crewai.tools import BaseTool
    except ImportError:
        print("Install: pip install crewai")
        return None

    class AgentShieldMonitor:
        """Monitor that wraps a crew and tracks all agent actions."""

        def __init__(self, server_url: str, api_key: str):
            self.server_url = server_url
            self.api_key = api_key
            self.events = []

        def record(self, agent_id: str, action: str, details: dict):
            from agentshield.ml.nlp_classifier import NLPClassifier
            clf = NLPClassifier()
            text = str(details)
            result = clf.classify(text)
            if result.is_malicious:
                print(f"[AgentShield ALERT] Malicious content from {agent_id}: {result.patterns_matched}")

            self.events.append({
                "event_type": "tool_call",
                "agent_id": agent_id,
                "action": action,
                "details": details,
            })

    monitor = AgentShieldMonitor(
        server_url=os.getenv("AGENTSHIELD_SERVER_URL", "http://localhost:8000"),
        api_key=os.getenv("AGENTSHIELD_API_KEY", "test-key"),
    )

    # Define agents
    researcher = Agent(
        role="Security Researcher",
        goal="Research security vulnerabilities in AI systems",
        backstory="Expert AI security researcher who identifies threats",
        verbose=True,
    )

    analyst = Agent(
        role="Threat Analyst",
        goal="Analyze findings and produce security reports",
        backstory="Experienced threat analyst with deep MITRE ATT&CK knowledge",
        verbose=True,
    )

    # Define tasks
    research_task = Task(
        description="Research the latest prompt injection techniques targeting LLM agents",
        expected_output="A list of 5 recent prompt injection techniques with examples",
        agent=researcher,
    )

    analysis_task = Task(
        description="Analyze the research findings and map to MITRE ATT&CK for AI",
        expected_output="A structured threat report with MITRE mappings",
        agent=analyst,
        context=[research_task],
    )

    crew = Crew(
        agents=[researcher, analyst],
        tasks=[research_task, analysis_task],
        process=Process.sequential,
        verbose=True,
    )

    return crew, monitor


if __name__ == "__main__":
    print("AgentShield + CrewAI Integration Example")
    print("=" * 50)

    result = create_protected_crew()
    if result is None:
        print("CrewAI not installed. Install with: pip install crewai")
        sys.exit(0)

    crew, monitor = result
    print(f"Crew configured with AgentShield monitoring")
    print(f"AgentShield server: {os.getenv('AGENTSHIELD_SERVER_URL', 'http://localhost:8000')}")

    if os.getenv("OPENAI_API_KEY"):
        result = crew.kickoff()
        print(f"\nCrew result: {result}")
        print(f"Events monitored: {len(monitor.events)}")
    else:
        print("Set OPENAI_API_KEY to run the crew.")
