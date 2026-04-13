"""
AgentShield core module.

Provides the main AgentShield class for initializing and managing
agent protection. Supports both global singleton and instance-based usage.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_global_instance: Optional["AgentShield"] = None


@dataclass
class AgentShieldConfig:
    """
    Configuration for AgentShield.

    Attributes:
        api_key: API key for authenticating with the AgentShield server
        server_url: Base URL of the AgentShield server
        org_id: Organization ID for multi-tenant setups
        environment: Deployment environment (dev/staging/prod)
        enable_blocking: Whether policy violations trigger blocking (default True)
        enable_pii_detection: Whether to scan outputs for PII (default True)
        enable_prompt_injection: Whether to scan inputs for injection (default True)
        enable_anomaly_detection: Whether to use anomaly detection (default True)
        offline_mode: Run without server connection (local logging only)
        audit_log_path: Path for local audit log file
        batch_events: Whether to batch events before sending (default True)
        batch_size: Number of events to batch before flushing (default 10)
        batch_interval_seconds: Max seconds before flushing batch (default 5)
        allowed_tools: Whitelist of tool names agent is allowed to call
        max_output_bytes: Maximum allowed output size before flagging exfil
    """

    api_key: str = ""
    server_url: str = "http://localhost:8000"
    org_id: str = ""
    environment: str = "development"
    enable_blocking: bool = True
    enable_pii_detection: bool = True
    enable_prompt_injection: bool = True
    enable_anomaly_detection: bool = True
    offline_mode: bool = False
    audit_log_path: str = "agentshield-audit.log"
    batch_events: bool = True
    batch_size: int = 10
    batch_interval_seconds: float = 5.0
    allowed_tools: list[str] = field(default_factory=list)
    max_output_bytes: int = 100_000


class AgentShield:
    """
    Main AgentShield class. Initialize once, protect many agents.

    Example:
        shield = AgentShield(AgentShieldConfig(api_key="key"))
        protected = shield.protect(my_agent)
    """

    def __init__(self, config: Optional[AgentShieldConfig] = None) -> None:
        """
        Initialize AgentShield with configuration.

        Args:
            config: Configuration object. If None, uses defaults (offline mode).
        """
        self.config = config or AgentShieldConfig(offline_mode=True)
        self._session_id = str(uuid.uuid4())
        self._interceptor: Optional[Any] = None
        self._policy_engine: Optional[Any] = None
        self._audit_logger: Optional[Any] = None
        self._transport: Optional[Any] = None
        self._initialized = False
        self._setup()

    def _setup(self) -> None:
        """Initialize all subsystems."""
        from .interceptor import Interceptor
        from .policies.engine import PolicyEngine
        from .audit.logger import AuditLogger

        self._audit_logger = AuditLogger(
            log_path=self.config.audit_log_path,
        )
        self._policy_engine = PolicyEngine(config=self.config)

        if self.config.offline_mode:
            from .transport.local import LocalTransport
            self._transport = LocalTransport(config=self.config)
        else:
            from .transport.http import HttpTransport
            self._transport = HttpTransport(config=self.config)

        self._interceptor = Interceptor(
            config=self.config,
            policy_engine=self._policy_engine,
            transport=self._transport,
            audit_logger=self._audit_logger,
        )

        self._initialized = True
        logger.info(
            f"AgentShield initialized | env={self.config.environment} "
            f"| offline={self.config.offline_mode} "
            f"| session={self._session_id}"
        )

    def protect(self, agent: Any, agent_name: Optional[str] = None) -> Any:
        """
        Wrap an agent with AgentShield protection.

        Automatically detects the agent framework and applies the appropriate wrapper.

        Args:
            agent: The agent object to protect
            agent_name: Optional human-readable name for this agent

        Returns:
            Wrapped agent with identical interface but with monitoring
        """
        if not self._initialized:
            raise RuntimeError("AgentShield not initialized")

        from .wrappers.generic import GenericWrapper
        from .wrappers.langchain import LangChainWrapper
        from .wrappers.crewai import CrewAIWrapper
        from .wrappers.autogen import AutoGenWrapper
        from .wrappers.openai_agents import OpenAIAgentsWrapper

        # Detect framework
        agent_class = type(agent).__module__

        wrapper_cls = GenericWrapper
        if "langchain" in agent_class:
            wrapper_cls = LangChainWrapper
        elif "crewai" in agent_class:
            wrapper_cls = CrewAIWrapper
        elif "autogen" in agent_class:
            wrapper_cls = AutoGenWrapper
        elif "openai" in agent_class and "agents" in agent_class:
            wrapper_cls = OpenAIAgentsWrapper

        wrapped = wrapper_cls(
            agent=agent,
            interceptor=self._interceptor,
            agent_name=agent_name or type(agent).__name__,
        )
        logger.info(f"Protected agent: {agent_name or type(agent).__name__} with {wrapper_cls.__name__}")
        return wrapped

    def kill(self, session_id: Optional[str] = None) -> None:
        """
        Kill a running agent session.

        Args:
            session_id: Session ID to kill. If None, kills current session.
        """
        target = session_id or self._session_id
        if self._interceptor:
            self._interceptor.kill_session(target)
        logger.warning(f"Kill switch activated for session: {target}")

    def get_session_id(self) -> str:
        """Return the current session ID."""
        return self._session_id

    def flush(self) -> None:
        """Flush any pending events to the transport."""
        if self._transport:
            self._transport.flush()

    def shutdown(self) -> None:
        """Gracefully shut down AgentShield and flush remaining events."""
        self.flush()
        if self._audit_logger:
            self._audit_logger.close()
        self._initialized = False
        logger.info("AgentShield shutdown complete")

    def __enter__(self) -> "AgentShield":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.shutdown()


def init(
    api_key: str = "",
    server_url: str = "http://localhost:8000",
    org_id: str = "",
    environment: str = "development",
    offline_mode: bool = False,
    **kwargs: Any,
) -> AgentShield:
    """
    Initialize the global AgentShield instance.

    This is the recommended way to initialize AgentShield for most use cases.

    Args:
        api_key: API key for authenticating with the AgentShield server
        server_url: Base URL of the AgentShield server
        org_id: Organization ID
        environment: Deployment environment
        offline_mode: Run without server connection
        **kwargs: Additional config options passed to AgentShieldConfig

    Returns:
        Initialized AgentShield instance
    """
    global _global_instance
    config = AgentShieldConfig(
        api_key=api_key,
        server_url=server_url,
        org_id=org_id,
        environment=environment,
        offline_mode=offline_mode,
        **kwargs,
    )
    _global_instance = AgentShield(config)
    return _global_instance


def protect(agent: Any, agent_name: Optional[str] = None) -> Any:
    """
    Protect an agent using the global AgentShield instance.

    Initializes with offline mode if not already initialized.

    Args:
        agent: The agent to protect
        agent_name: Optional name for the agent

    Returns:
        Protected agent wrapper
    """
    global _global_instance
    if _global_instance is None:
        _global_instance = AgentShield(AgentShieldConfig(offline_mode=True))
        logger.warning(
            "AgentShield auto-initialized in offline mode. "
            "Call agentshield.init() for full protection."
        )
    return _global_instance.protect(agent, agent_name)


def get_instance() -> Optional[AgentShield]:
    """Return the global AgentShield instance, or None if not initialized."""
    return _global_instance
