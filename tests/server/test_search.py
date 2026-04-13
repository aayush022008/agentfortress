"""Tests for search service."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../"))

from server.services.search_service import SearchService


class TestSearchService:
    def test_index_and_search(self):
        svc = SearchService()
        svc.index("evt-001", "event", "bash command injection detected", {"tool_name": "bash"}, 1000.0)
        svc.index("evt-002", "event", "read file credentials", {"tool_name": "read_file"}, 1001.0)
        svc.index("evt-003", "alert", "prompt injection attempt blocked", {"severity": "high"}, 1002.0)

        results, total = svc.search("injection")
        assert total >= 2
        ids = [r.doc_id for r in results]
        assert "evt-001" in ids
        assert "evt-003" in ids

    def test_search_no_results(self):
        svc = SearchService()
        svc.index("doc-001", "event", "normal event nothing suspicious", {})
        results, total = svc.search("zzznomatchxxx")
        assert total == 0

    def test_filter_by_doc_type(self):
        svc = SearchService()
        svc.index("evt-001", "event", "security alert injection", {})
        svc.index("alt-001", "alert", "security alert injection", {})
        results, total = svc.search("injection", doc_type="alert")
        assert all(r.doc_type == "alert" for r in results)

    def test_filter_by_time(self):
        svc = SearchService()
        svc.index("old", "event", "old event data", {}, timestamp=100.0)
        svc.index("new", "event", "new event data", {}, timestamp=9999.0)
        results, total = svc.search("event", start_time=500.0)
        ids = [r.doc_id for r in results]
        assert "new" in ids
        assert "old" not in ids

    def test_delete_document(self):
        svc = SearchService()
        svc.index("doc-del", "event", "delete this document", {})
        results, total = svc.search("delete")
        assert total >= 1
        svc.delete("doc-del")
        results2, total2 = svc.search("delete")
        ids = [r.doc_id for r in results2]
        assert "doc-del" not in ids

    def test_stats(self):
        svc = SearchService()
        svc.index("d1", "event", "hello world security", {})
        stats = svc.stats()
        assert stats["total_documents"] >= 1
        assert stats["unique_terms"] >= 1

    def test_highlights_generated(self):
        svc = SearchService()
        svc.index("d1", "event", "prompt injection attack detected by agentshield", {})
        results, _ = svc.search("injection", highlight=True)
        if results:
            assert "content" in results[0].highlights


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
