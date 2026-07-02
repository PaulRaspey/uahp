"""UAHP Stack v1.0 — Trust infrastructure for autonomous agents."""
from .core import UAHPCore, AgentIdentity, Receipt, DeathCertificate, HandshakeResult
from .reputation import ReputationEngine, TrustProfile
from .compliance import ComplianceEngine, ComplianceReport
from .a2a import A2AIntegration, UAHPAgentCard
from .mcp_server import UAHPMCPServer

__version__ = "1.0.0"
__author__ = "Paul Raspey"
