"""AgentShield deception module — honeypots, canaries, decoys."""
from .honeytokens import HoneytokenManager, Honeytoken
from .canary_files import CanaryFileManager
from .decoy_endpoints import DecoyEndpointServer

__all__ = ["HoneytokenManager", "Honeytoken", "CanaryFileManager", "DecoyEndpointServer"]
