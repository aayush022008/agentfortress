"""
Network policy enforcement for sandboxed agents.
Supports allowlist/blocklist for outbound connections.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Pattern, Tuple

logger = logging.getLogger(__name__)


@dataclass
class NetworkPolicy:
    """Defines outbound network rules for a sandboxed agent."""

    mode: str = "allowlist"
    """'allowlist' (default-deny) or 'blocklist' (default-allow)."""

    allowed_hosts: List[str] = field(default_factory=list)
    """Hostnames / IP prefixes that are explicitly allowed (allowlist mode)."""

    blocked_hosts: List[str] = field(default_factory=list)
    """Hostnames / IP prefixes that are explicitly blocked (blocklist mode)."""

    allowed_ports: List[int] = field(default_factory=lambda: [80, 443])
    """TCP ports that are allowed outbound."""

    blocked_ports: List[int] = field(default_factory=list)
    """TCP ports that are explicitly blocked."""

    log_violations: bool = True
    """Whether to log policy violations."""


class NetworkEnforcer:
    """
    Enforces a NetworkPolicy by monkey-patching socket.create_connection
    and urllib.request.urlopen at the Python level.

    For stronger enforcement in subprocesses, combine with an iptables/nftables
    rule or a Kubernetes NetworkPolicy.
    """

    def __init__(self, policy: NetworkPolicy) -> None:
        self.policy = policy
        self._violations: List[Dict[str, str]] = []
        self._original_create_connection = socket.create_connection
        self._active = False

    def __enter__(self) -> "NetworkEnforcer":
        self.install()
        return self

    def __exit__(self, *_: object) -> None:
        self.uninstall()

    def install(self) -> None:
        """Monkey-patch socket.create_connection."""
        if self._active:
            return
        enforcer = self

        def patched_create_connection(
            address: Tuple[str, int],
            timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore[attr-defined]
            source_address: Optional[Tuple[str, int]] = None,
        ) -> socket.socket:
            host, port = address
            enforcer._check_connection(host, port)
            return enforcer._original_create_connection(
                address, timeout, source_address
            )

        socket.create_connection = patched_create_connection  # type: ignore[assignment]
        self._active = True

    def uninstall(self) -> None:
        """Restore original socket.create_connection."""
        if not self._active:
            return
        socket.create_connection = self._original_create_connection  # type: ignore[assignment]
        self._active = False

    def is_allowed(self, host: str, port: int) -> bool:
        """Return True if an outbound connection to host:port is permitted."""
        policy = self.policy

        # Port check
        if port in policy.blocked_ports:
            return False
        if policy.allowed_ports and port not in policy.allowed_ports:
            return False

        if policy.mode == "allowlist":
            for allowed in policy.allowed_hosts:
                if self._host_matches(host, allowed):
                    return True
            return False
        else:  # blocklist
            for blocked in policy.blocked_hosts:
                if self._host_matches(host, blocked):
                    return False
            return True

    def list_violations(self) -> List[Dict[str, str]]:
        return list(self._violations)

    # ------------------------------------------------------------------

    def _check_connection(self, host: str, port: int) -> None:
        if not self.is_allowed(host, port):
            import datetime
            violation = {
                "host": host,
                "port": str(port),
                "timestamp": datetime.datetime.utcnow().isoformat(),
            }
            self._violations.append(violation)
            if self.policy.log_violations:
                logger.warning(
                    "AgentShield: blocked outbound connection %s:%s", host, port
                )
            raise PermissionError(
                f"AgentShield sandbox: outbound connection to {host}:{port} denied by policy"
            )

    @staticmethod
    def _host_matches(host: str, pattern: str) -> bool:
        """Match a host against a pattern that may be a hostname, IP, or CIDR."""
        # Exact match
        if host == pattern:
            return True
        # Wildcard hostname (e.g. *.example.com)
        if pattern.startswith("*."):
            suffix = pattern[1:]  # .example.com
            if host.endswith(suffix):
                return True
        # CIDR match
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in network
        except ValueError:
            pass
        return False
