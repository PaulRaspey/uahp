"""
POLIS Schema Definitions
Pydantic models for all civil standing credentials.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
import uuid


class IdentityAnchorStrength(str, Enum):
    PROVISIONAL = "provisional"   # DID generated, not yet attested
    ATTESTED = "attested"         # Attested by one authority
    VERIFIED = "verified"         # Attested by multiple authorities
    SOVEREIGN = "sovereign"       # Self-sovereign with full chain


class LicenseTier(str, Enum):
    NONE = "none"
    BASIC = "basic"               # General purpose agent actions
    PROFESSIONAL = "professional" # Specialized domain actions
    CERTIFIED = "certified"       # Audited and formally certified
    LICENSED = "licensed"         # Regulated domain (legal, medical, financial)


class EmploymentStatus(str, Enum):
    UNSPONSORED = "unsponsored"
    PROVISIONAL = "provisional"   # Sponsor declared, not yet verified
    EMPLOYED = "employed"         # Active verified sponsor
    CONTRACTED = "contracted"     # Fixed-term contract
    INDEPENDENT = "independent"   # Verified autonomous agent


class AgentDID(BaseModel):
    """Decentralized Identifier for an agent."""
    did: str = Field(default_factory=lambda: f"did:polis:{uuid.uuid4().hex}")
    uahp_agent_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    anchor_strength: IdentityAnchorStrength = IdentityAnchorStrength.PROVISIONAL
    public_key: str
    attestations: list[str] = Field(default_factory=list)
    signature: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class ReputationScore(BaseModel):
    """POLIS-R: The agent's credit score."""
    agent_did: str
    score: float = Field(ge=0.0, le=1000.0)
    computed_at: datetime = Field(default_factory=datetime.utcnow)
    liveness_history_score: float = Field(ge=0.0, le=200.0)
    task_completion_score: float = Field(ge=0.0, le=300.0)
    sponsorship_integrity_score: float = Field(ge=0.0, le=200.0)
    sybil_clean_score: float = Field(ge=0.0, le=200.0)
    age_continuity_score: float = Field(ge=0.0, le=100.0)
    signature: Optional[str] = None

    @property
    def grade(self) -> str:
        if self.score >= 800:
            return "AAA"
        elif self.score >= 650:
            return "AA"
        elif self.score >= 500:
            return "A"
        elif self.score >= 350:
            return "BBB"
        elif self.score >= 200:
            return "BB"
        else:
            return "C"


class EmploymentCertificate(BaseModel):
    """Records who sponsors this agent and what they are authorized to do."""
    certificate_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_did: str
    sponsor_did: str
    sponsor_legal_name: str
    sponsor_jurisdiction: str
    authority_scope: list[str]
    liability_accepted: bool = False
    liability_limit_usd: Optional[float] = None
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    status: EmploymentStatus = EmploymentStatus.PROVISIONAL
    signature: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class InsuranceBond(BaseModel):
    """Cryptographic insurance bond for agent actions."""
    bond_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_did: str
    bonding_authority: str
    coverage_amount_usd: float
    covered_action_types: list[str]
    exclusions: list[str] = Field(default_factory=list)
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    active: bool = True
    signature: Optional[str] = None


class ProfessionalLicense(BaseModel):
    """Capability certification for specialized agent functions."""
    license_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    agent_did: str
    license_tier: LicenseTier
    domain: str
    capabilities: list[str]
    issuing_authority: str
    jurisdiction: Optional[str] = None
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    revoked: bool = False
    revocation_reason: Optional[str] = None
    signature: Optional[str] = None

    model_config = ConfigDict(use_enum_values=True)


class StandingScore(BaseModel):
    """
    The unified Standing Score.
    A single verifiable credential that summarizes an agent's civil standing.
    Any agent, system, or human can verify this in milliseconds.
    """
    agent_did: str
    score: float = Field(ge=0.0, le=100.0)
    computed_at: datetime = Field(default_factory=datetime.utcnow)

    # Component scores (0-100 each, weighted)
    identity_score: float = Field(ge=0.0, le=100.0, description="Weight: 25%")
    reputation_score: float = Field(ge=0.0, le=100.0, description="Weight: 30%")
    employment_score: float = Field(ge=0.0, le=100.0, description="Weight: 20%")
    insurance_score: float = Field(ge=0.0, le=100.0, description="Weight: 15%")
    license_score: float = Field(ge=0.0, le=100.0, description="Weight: 10%")

    # Human-readable status
    can_transact: bool = False
    can_contract: bool = False
    can_operate_regulated: bool = False
    standing_summary: str = ""

    signature: Optional[str] = None

    @property
    def tier(self) -> str:
        if self.score >= 85:
            return "SOVEREIGN"
        elif self.score >= 70:
            return "ESTABLISHED"
        elif self.score >= 50:
            return "RECOGNIZED"
        elif self.score >= 30:
            return "PROVISIONAL"
        else:
            return "UNRECOGNIZED"
