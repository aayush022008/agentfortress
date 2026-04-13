"""Tests for sandbox module."""
import asyncio
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../sdk"))

from agentshield.sandbox.executor import SandboxConfig, SandboxExecutor
from agentshield.sandbox.filesystem import FilesystemPolicy, VirtualFilesystem
from agentshield.sandbox.network import NetworkEnforcer, NetworkPolicy
from agentshield.sandbox.resource_monitor import ResourceMonitor


class TestSandboxExecutor:
    def test_config_defaults(self):
        config = SandboxConfig()
        assert config.max_memory_mb == 512
        assert config.max_cpu_percent == 80.0
        assert config.max_duration_seconds == 300.0

    def test_run_simple_script(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello sandbox')\n")
            script_path = f.name
        try:
            config = SandboxConfig(max_duration_seconds=5.0)
            executor = SandboxExecutor(config)
            result = asyncio.run(executor.run_script(script_path))
            assert result.exit_code == 0
            assert "hello sandbox" in result.stdout
            assert not result.killed_by_timeout
            assert not result.killed_by_oom
        finally:
            os.unlink(script_path)

    def test_timeout_enforcement(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("import time; time.sleep(60)\n")
            script_path = f.name
        try:
            config = SandboxConfig(max_duration_seconds=1.0)
            executor = SandboxExecutor(config)
            result = asyncio.run(executor.run_script(script_path))
            assert result.killed_by_timeout
        finally:
            os.unlink(script_path)


class TestVirtualFilesystem:
    def test_allowed_read(self):
        with VirtualFilesystem() as fs:
            assert fs.scratch_dir is not None
            assert fs.check_read(fs.scratch_dir)

    def test_blocked_path(self):
        policy = FilesystemPolicy(
            allowed_read_paths=["/tmp"],
            blocked_paths=["/etc"],
        )
        fs = VirtualFilesystem(policy)
        assert not fs.check_read("/etc/passwd")
        assert fs.check_read("/tmp/something")

    def test_enforce_raises(self):
        policy = FilesystemPolicy(allowed_read_paths=["/tmp"])
        fs = VirtualFilesystem(policy)
        with pytest.raises(PermissionError):
            fs.enforce_read("/etc/shadow")

    def test_canary_file_creation(self):
        with VirtualFilesystem() as fs:
            canary_path = fs.create_canary_file("test_canary.txt")
            assert os.path.exists(canary_path)
            assert "CANARY" in open(canary_path).read()


class TestNetworkEnforcer:
    def test_allowlist_mode(self):
        policy = NetworkPolicy(
            mode="allowlist",
            allowed_hosts=["api.openai.com", "*.anthropic.com"],
            allowed_ports=[443],
        )
        enforcer = NetworkEnforcer(policy)
        assert enforcer.is_allowed("api.openai.com", 443)
        assert enforcer.is_allowed("api.anthropic.com", 443)
        assert not enforcer.is_allowed("attacker.com", 443)
        assert not enforcer.is_allowed("api.openai.com", 80)

    def test_blocklist_mode(self):
        policy = NetworkPolicy(
            mode="blocklist",
            blocked_hosts=["attacker.com"],
            allowed_ports=[443, 80],
        )
        enforcer = NetworkEnforcer(policy)
        assert enforcer.is_allowed("google.com", 443)
        assert not enforcer.is_allowed("attacker.com", 443)

    def test_cidr_matching(self):
        policy = NetworkPolicy(
            mode="allowlist",
            allowed_hosts=["192.168.1.0/24"],
            allowed_ports=[443],
        )
        enforcer = NetworkEnforcer(policy)
        assert enforcer.is_allowed("192.168.1.100", 443)
        assert not enforcer.is_allowed("10.0.0.1", 443)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
