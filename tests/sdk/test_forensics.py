"""Tests for forensics modules."""
import os
import sys
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.forensics.snapshot import AgentSnapshot, SnapshotManager
from agentshield.forensics.diff import diff_snapshots
from agentshield.forensics.timeline import IncidentTimeline
from agentshield.forensics.evidence import EvidencePackage
from agentshield.forensics.chain_of_custody import ChainOfCustody


class TestSnapshotManager:
    def test_take_and_load_snapshot(self, tmp_path):
        mgr = SnapshotManager(storage_dir=str(tmp_path))
        snap = mgr.take_snapshot(
            agent_id="agent-001",
            session_id="sess-001",
            context={"messages": ["hello"], "memory": {}},
            tool_state={"open_files": []},
            metadata={"test": True},
        )
        assert snap.snapshot_id
        assert snap.agent_id == "agent-001"

        loaded = mgr.load_snapshot(snap.snapshot_id)
        assert loaded is not None
        assert loaded.agent_id == "agent-001"
        assert loaded.context["messages"] == ["hello"]

    def test_list_snapshots(self, tmp_path):
        mgr = SnapshotManager(storage_dir=str(tmp_path))
        mgr.take_snapshot("agent-001", "sess-001", {})
        mgr.take_snapshot("agent-001", "sess-002", {})
        mgr.take_snapshot("agent-002", "sess-003", {})

        all_snaps = mgr.list_snapshots()
        assert len(all_snaps) == 3

        agent_snaps = mgr.list_snapshots(agent_id="agent-001")
        assert len(agent_snaps) == 2

    def test_delete_snapshot(self, tmp_path):
        mgr = SnapshotManager(storage_dir=str(tmp_path))
        snap = mgr.take_snapshot("agent-001", "sess-001", {})
        assert mgr.delete_snapshot(snap.snapshot_id)
        assert mgr.load_snapshot(snap.snapshot_id) is None


class TestSnapshotDiff:
    def test_detect_context_change(self):
        before = AgentSnapshot(
            snapshot_id="s1", agent_id="a1", session_id="sess-1",
            timestamp=time.time(), events_count=5, last_event=None,
            context={"memory": {"key": "value1"}, "step": 1},
            tool_state={},
        )
        after = AgentSnapshot(
            snapshot_id="s2", agent_id="a1", session_id="sess-1",
            timestamp=time.time() + 10, events_count=8, last_event=None,
            context={"memory": {"key": "value2"}, "step": 2},
            tool_state={},
        )
        diff = diff_snapshots(before, after)
        assert diff.has_changes()
        assert diff.events_added == 3
        paths = [d.path for d in diff.context_changes]
        assert any("key" in p for p in paths)


class TestIncidentTimeline:
    def test_ingest_and_build_report(self):
        timeline = IncidentTimeline()
        events = [
            {"event_type": "tool_call", "timestamp": 1710000000, "severity": "info", "agent_id": "a1", "session_id": "s1"},
            {"event_type": "alert", "timestamp": 1710000010, "severity": "critical", "agent_id": "a1", "session_id": "s1", "description": "Injection detected"},
            {"event_type": "alert", "timestamp": 1710000020, "severity": "high", "agent_id": "a1", "session_id": "s1", "description": "Data exfiltration attempt"},
        ]
        count = timeline.ingest_events(events)
        assert count == 3

        report = timeline.build_report("INC-001")
        assert report.incident_id == "INC-001"
        assert len(report.events) == 3
        assert report.severity in ("critical", "high")
        assert "a1" in report.affected_agents

    def test_filter_by_time(self):
        timeline = IncidentTimeline()
        events = [
            {"event_type": "e1", "timestamp": 1000, "severity": "info"},
            {"event_type": "e2", "timestamp": 2000, "severity": "info"},
            {"event_type": "e3", "timestamp": 3000, "severity": "info"},
        ]
        timeline.ingest_events(events)
        report = timeline.build_report("INC-002", start_time=1500, end_time=2500)
        assert len(report.events) == 1


class TestEvidencePackage:
    def test_seal_package(self, tmp_path):
        pkg = EvidencePackage(case_id="CASE-001", investigator="Alice", description="Test")
        events = [{"event_type": "alert", "severity": "critical"}]
        pkg.add_events(events, "Test events")
        pkg.add_metadata({"case": "test"})

        output_path = str(tmp_path / "evidence.tar.gz")
        sealed_path = pkg.seal(output_path)
        assert os.path.exists(sealed_path)
        pkg.cleanup()

    def test_add_multiple_items(self, tmp_path):
        pkg = EvidencePackage(investigator="Bob")
        pkg.add_events([{"event": 1}, {"event": 2}])
        pkg.add_metadata({"case_type": "test"})
        output = str(tmp_path / "test.tar.gz")
        pkg.seal(output)
        assert os.path.exists(output)
        pkg.cleanup()


class TestChainOfCustody:
    def test_record_and_verify(self, tmp_path):
        coc = ChainOfCustody(case_id="CASE-001")
        coc.generate_keypair()

        coc.record("collected", "alice", "Collected audit logs", "abc123hash")
        coc.record("transferred", "bob", "Transferred to team", "def456hash")

        assert coc.verify()

    def test_save_and_load(self, tmp_path):
        coc_path = str(tmp_path / "coc.json")
        coc = ChainOfCustody(case_id="CASE-002")
        coc.generate_keypair()
        coc.record("collected", "alice", "Initial collection", "hash1")
        coc.save(coc_path)

        loaded = ChainOfCustody.load(coc_path)
        assert loaded.case_id == "CASE-002"
        assert len(loaded.get_entries()) == 1
        # Can't verify without key after load (no private key)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
