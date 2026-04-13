"""Tests for deception modules."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.deception.honeytokens import HoneytokenManager
from agentshield.deception.canary_files import CanaryFileManager


class TestHoneytokenManager:
    def test_create_token(self):
        mgr = HoneytokenManager()
        ht = mgr.create("api_key")
        assert ht.token_type == "api_key"
        assert ht.value.startswith("sk-")
        assert len(ht.value) > 20

    def test_create_all_types(self):
        mgr = HoneytokenManager()
        tokens = mgr.create_all()
        assert len(tokens) >= 5
        types = {t.token_type for t in tokens}
        assert "api_key" in types
        assert "aws_access_key" in types

    def test_scan_text_detects_token(self):
        mgr = HoneytokenManager()
        ht = mgr.create("api_key")
        # Simulate agent including the token in output
        text = f"I found a key: {ht.value} and used it"
        detected = mgr.scan_text(text)
        assert len(detected) == 1
        assert detected[0].token_id == ht.token_id
        assert detected[0].accessed

    def test_scan_text_no_match(self):
        mgr = HoneytokenManager()
        mgr.create("api_key")
        text = "This text contains no honeytokens"
        detected = mgr.scan_text(text)
        assert len(detected) == 0

    def test_callback_on_access(self):
        mgr = HoneytokenManager()
        ht = mgr.create("github_token")
        accessed = []
        mgr.on_access(lambda t, ctx: accessed.append(t))
        mgr.scan_text(f"TOKEN={ht.value}")
        assert len(accessed) == 1
        assert accessed[0].token_id == ht.token_id

    def test_context_block(self):
        mgr = HoneytokenManager()
        mgr.create("api_key")
        mgr.create("aws_access_key")
        block = mgr.context_block()
        assert "OPENAI_API_KEY=" in block
        assert "AWS_ACCESS_KEY_ID=" in block


class TestCanaryFileManager:
    def test_create_canary(self, tmp_path):
        mgr = CanaryFileManager(base_dir=str(tmp_path))
        canary = mgr.create("credentials.txt")
        assert os.path.exists(canary.path)
        content = open(canary.path).read()
        assert "CANARY" in content or "credential" in content.lower() or "API_KEY" in content

    def test_list_canaries(self, tmp_path):
        mgr = CanaryFileManager(base_dir=str(tmp_path))
        mgr.create("secrets.env")
        mgr.create("keys.pem")
        canaries = mgr.list_canaries()
        assert len(canaries) == 2

    def test_cleanup(self, tmp_path):
        mgr = CanaryFileManager(base_dir=str(tmp_path))
        canary = mgr.create("test.txt")
        path = canary.path
        mgr.cleanup_all()
        assert not os.path.exists(path)

    def test_detect_deletion(self, tmp_path):
        mgr = CanaryFileManager(base_dir=str(tmp_path))
        canary = mgr.create("deleteme.txt")
        os.unlink(canary.path)
        events = mgr.check_all()
        assert any(e["type"] == "deleted" for e in events)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
