"""Tests for IOC manager."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from threat_intel.engine.ioc_manager import IOCManager


class TestIOCManager:
    def test_add_and_match(self):
        mgr = IOCManager()
        mgr.add("ip", "1.2.3.4", severity="high")
        matches = mgr.match_text("connection from 1.2.3.4 blocked")
        assert len(matches) == 1
        assert matches[0].value == "1.2.3.4"
        assert matches[0].hit_count == 1

    def test_no_match(self):
        mgr = IOCManager()
        mgr.add("ip", "1.2.3.4")
        matches = mgr.match_text("completely clean text")
        assert len(matches) == 0

    def test_bulk_ingest(self):
        mgr = IOCManager()
        iocs = [
            {"type": "ip", "value": "10.0.0.1", "severity": "high"},
            {"type": "domain", "value": "attacker.com", "severity": "critical"},
            {"type": "hash", "value": "abc123def456", "severity": "medium"},
        ]
        count = mgr.add_bulk(iocs)
        assert count == 3

    def test_match_event(self):
        mgr = IOCManager()
        mgr.add("domain", "malicious.example.com")
        event = {"tool_name": "http_post", "tool_input": {"url": "https://malicious.example.com/exfil"}}
        matches = mgr.match_event(event)
        assert len(matches) == 1

    def test_expired_ioc_not_matched(self):
        import time
        mgr = IOCManager()
        mgr.add("ip", "1.2.3.4", ttl_days=-1)  # Already expired
        matches = mgr.match_text("ip: 1.2.3.4")
        assert len(matches) == 0

    def test_false_positive_excluded(self):
        mgr = IOCManager()
        ioc = mgr.add("domain", "legitimate.com")
        mgr.mark_false_positive(ioc.ioc_id)
        matches = mgr.match_text("request to legitimate.com")
        assert len(matches) == 0

    def test_save_and_load(self, tmp_path):
        path = str(tmp_path / "iocs.json")
        mgr = IOCManager()
        mgr.add("ip", "5.5.5.5", description="Test IOC")
        mgr.save(path)

        mgr2 = IOCManager()
        count = mgr2.load(path)
        assert count == 1
        matches = mgr2.match_text("connection to 5.5.5.5")
        assert len(matches) == 1

    def test_stats(self):
        mgr = IOCManager()
        mgr.add("ip", "1.1.1.1", severity="high")
        mgr.add("domain", "bad.com", severity="critical")
        stats = mgr.stats()
        assert stats["total"] == 2
        assert stats["by_severity"]["high"] == 1
        assert stats["by_severity"]["critical"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
