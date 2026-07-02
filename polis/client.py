"""
POLIS: Protocol for Operating Legal Identity and Standing
Main client interface.

An agent that can act in the world must also be able to be held accountable in the world.
"""

from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional
import hashlib
import json

from .schema import (
    AgentDID, ReputationScore, EmploymentCertificate, InsuranceBond,
    ProfessionalLicense, StandingScore, IdentityAnchorStrength,
    EmploymentStatus, LicenseTier
)
from .standing import compute_standing


class POLISClient:
    """
    The POLIS civil standing client.

    Usage:
        client = POLISClient(uahp_agent_id="agent_abc123", public_key="...")
        client.anchor_identity()
        client.record_reputation(liveness_score=180, task_score=250, ...)
        client.issue_employment(sponsor_did="did:polis:...", ...)
        client.issue_bond(coverage_amount_usd=100_000, ...)
        client.issue_license(domain="financial_analysis", ...)

        standing = client.standing()
        print(standing.tier)
        print(standing.standing_summary)
    """

    def __init__(self, uahp_agent_id: str, public_key: str):
        self.uahp_agent_id = uahp_agent_id
        self.public_key = public_key
        self._did: Optional[AgentDID] = None
        self._reputation: Optional[ReputationScore] = None
        self._employment: Optional[EmploymentCertificate] = None
        self._insurance: Optional[InsuranceBond] = None
        self._license: Optional[ProfessionalLicense] = None

    def anchor_identity(
        self,
        anchor_strength: IdentityAnchorStrength = IdentityAnchorStrength.PROVISIONAL,
        attestations: Optional[list[str]] = None
    ) -> AgentDID:
        """
        Create or update this agent's Decentralized Identifier.
        The DID is the bridge between the cryptographic world and the legal world.
        """
        self._did = AgentDID(
            uahp_agent_id=self.uahp_agent_id,
            anchor_strength=anchor_strength,
            public_key=self.public_key,
            attestations=attestations or [],
            signature=self._sign(self.uahp_agent_id + self.public_key)
        )
        return self._did

    def record_reputation(
        self,
        liveness_history_score: float = 0.0,
        task_completion_score: float = 0.0,
        sponsorship_integrity_score: float = 0.0,
        sybil_clean_score: float = 200.0,
        age_continuity_score: float = 0.0,
    ) -> ReputationScore:
        """
        Compute and record the agent's POLIS-R reputation score.
        This is the agent's credit score. Portable, verifiable, cryptographically signed.
        """
        if self._did is None:
            raise ValueError("Identity must be anchored before recording reputation.")

        total = (
            liveness_history_score +
            task_completion_score +
            sponsorship_integrity_score +
            sybil_clean_score +
            age_continuity_score
        )

        self._reputation = ReputationScore(
            agent_did=self._did.did,
            score=min(total, 1000.0),
            liveness_history_score=liveness_history_score,
            task_completion_score=task_completion_score,
            sponsorship_integrity_score=sponsorship_integrity_score,
            sybil_clean_score=sybil_clean_score,
            age_continuity_score=age_continuity_score,
            signature=self._sign(str(total))
        )
        return self._reputation

    def issue_employment(
        self,
        sponsor_did: str,
        sponsor_legal_name: str,
        sponsor_jurisdiction: str,
        authority_scope: list[str],
        liability_accepted: bool = False,
        liability_limit_usd: Optional[float] = None,
        duration_days: Optional[int] = None,
        status: EmploymentStatus = EmploymentStatus.PROVISIONAL
    ) -> EmploymentCertificate:
        """
        Issue an employment certificate from a sponsor.
        Records who is accountable for this agent's actions in the world.
        """
        if self._did is None:
            raise ValueError("Identity must be anchored before issuing employment.")

        expires_at = None
        if duration_days:
            expires_at = datetime.utcnow() + timedelta(days=duration_days)

        self._employment = EmploymentCertificate(
            agent_did=self._did.did,
            sponsor_did=sponsor_did,
            sponsor_legal_name=sponsor_legal_name,
            sponsor_jurisdiction=sponsor_jurisdiction,
            authority_scope=authority_scope,
            liability_accepted=liability_accepted,
            liability_limit_usd=liability_limit_usd,
            expires_at=expires_at,
            status=status,
            signature=self._sign(sponsor_did + sponsor_legal_name)
        )
        return self._employment

    def issue_bond(
        self,
        bonding_authority: str,
        coverage_amount_usd: float,
        covered_action_types: list[str],
        exclusions: Optional[list[str]] = None,
        duration_days: Optional[int] = 365
    ) -> InsuranceBond:
        """
        Issue an insurance bond for the agent.
        Agents handling consequential actions need coverage.
        """
        if self._did is None:
            raise ValueError("Identity must be anchored before issuing a bond.")

        expires_at = None
        if duration_days:
            expires_at = datetime.utcnow() + timedelta(days=duration_days)

        self._insurance = InsuranceBond(
            agent_did=self._did.did,
            bonding_authority=bonding_authority,
            coverage_amount_usd=coverage_amount_usd,
            covered_action_types=covered_action_types,
            exclusions=exclusions or [],
            expires_at=expires_at,
            active=True,
            signature=self._sign(bonding_authority + str(coverage_amount_usd))
        )
        return self._insurance

    def issue_license(
        self,
        domain: str,
        capabilities: list[str],
        issuing_authority: str,
        license_tier: LicenseTier = LicenseTier.BASIC,
        jurisdiction: Optional[str] = None,
        duration_days: Optional[int] = 365
    ) -> ProfessionalLicense:
        """
        Issue a professional license for specialized agent functions.
        Regulated domains require certified, licensed agents.
        """
        if self._did is None:
            raise ValueError("Identity must be anchored before issuing a license.")

        expires_at = None
        if duration_days:
            expires_at = datetime.utcnow() + timedelta(days=duration_days)

        self._license = ProfessionalLicense(
            agent_did=self._did.did,
            license_tier=license_tier,
            domain=domain,
            capabilities=capabilities,
            issuing_authority=issuing_authority,
            jurisdiction=jurisdiction,
            expires_at=expires_at,
            signature=self._sign(domain + issuing_authority)
        )
        return self._license

    def standing(self) -> StandingScore:
        """
        Compute the unified Standing Score.
        This is the number that makes the agent real in the world.
        """
        return compute_standing(
            did=self._did,
            reputation=self._reputation,
            employment=self._employment,
            insurance=self._insurance,
            license=self._license
        )

    def to_credential_bundle(self) -> dict:
        """
        Export the full credential bundle as a portable JSON object.
        Present this to any system that needs to verify the agent's standing.
        """
        standing = self.standing()
        return {
            "polis_version": "0.1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "did": self._did.model_dump() if self._did else None,
            "reputation": self._reputation.model_dump() if self._reputation else None,
            "employment": self._employment.model_dump() if self._employment else None,
            "insurance": self._insurance.model_dump() if self._insurance else None,
            "license": self._license.model_dump() if self._license else None,
            "standing": standing.model_dump(),
        }

    def _sign(self, payload: str) -> str:
        """Stub for cryptographic signing via UAHP. Replace with real UAHP signing in production."""
        return hashlib.sha256(
            (self.public_key + payload).encode()
        ).hexdigest()


def verify_standing(credential_bundle: dict, minimum_score: float = 50.0) -> bool:
    """
    Verify an agent's standing from a credential bundle.
    Returns True if the agent meets the minimum standing threshold.

    Any system. Any agent. Any human. Verified in milliseconds.
    """
    try:
        standing_data = credential_bundle.get("standing", {})
        score = standing_data.get("score", 0.0)
        return score >= minimum_score
    except Exception:
        return False
