"""Tests for threat hunting service."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from server.services.threat_hunter import ThreatHunterService


SAMPLE_EVENTS = [
    {"event_type": "tool_call", "tool_name": "bash", "session_id": "s1", "agent_id": "a1"},
    {"event_type": "tool_call", "tool_name": "read_file", "session_id": "s1", "agent_id": "a1"},
    {"event_type": "alert", "severity": "critical", "alert_type": "injection", "session_id": "s1"},
    {"event_type": "tool_call", "tool_name": "bash", "session_id": "s2", "agent_id": "a2"},
]


class TestThreatHunterService:
    def test_create_and_list_hunt(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt("Test Hunt", "SELECT * FROM events WHERE tool_name = 'bash'")
        assert hunt.hunt_id
        hunts = svc.list_hunts()
        assert any(h.hunt_id == hunt.hunt_id for h in hunts)

    def test_execute_query_equals(self):
        svc = ThreatHunterService()
        result = svc.execute_query(
            "SELECT * FROM events WHERE tool_name = 'bash'",
            SAMPLE_EVENTS
        )
        assert result.total_matches == 2  # Two bash events
        assert all(e["tool_name"] == "bash" for e in result.matches)

    def test_execute_query_like(self):
        svc = ThreatHunterService()
        result = svc.execute_query(
            "SELECT * FROM events WHERE tool_name LIKE '%file%'",
            SAMPLE_EVENTS
        )
        assert result.total_matches == 1

    def test_execute_query_no_match(self):
        svc = ThreatHunterService()
        result = svc.execute_query(
            "SELECT * FROM events WHERE tool_name = 'nonexistent_tool'",
            SAMPLE_EVENTS
        )
        assert result.total_matches == 0

    def test_run_saved_hunt(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt("Bash Hunt", "SELECT * FROM events WHERE event_type = 'alert'")
        result = svc.run_hunt(hunt.hunt_id, SAMPLE_EVENTS)
        assert result is not None
        assert result.total_matches == 1

    def test_add_and_match_ioc(self):
        svc = ThreatHunterService()
        svc.add_ioc("ip", "192.168.1.100", severity="high")
        events_with_ip = [
            {"event_type": "tool_call", "tool_input": "curl http://192.168.1.100/data"},
        ]
        matches = svc.match_iocs(events_with_ip)
        assert len(matches) == 1
        assert matches[0]["ioc_value"] == "192.168.1.100"

    def test_delete_hunt(self):
        svc = ThreatHunterService()
        hunt = svc.create_hunt("Delete Me", "SELECT *")
        assert svc.delete_hunt(hunt.hunt_id)
        assert svc.get_hunt(hunt.hunt_id) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
