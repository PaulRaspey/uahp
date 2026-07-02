"""
POLIS Standing Score Engine
Computes the unified civil standing of an agent across all five dimensions.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from .schema import (
    AgentDID, ReputationScore, EmploymentCertificate,
    InsuranceBond, ProfessionalLicense, StandingScore,
    IdentityAnchorStrength, EmploymentStatus, LicenseTier
)


IDENTITY_WEIGHT = 0.25
REPUTATION_WEIGHT = 0.30
EMPLOYMENT_WEIGHT = 0.20
INSURANCE_WEIGHT = 0.15
LICENSE_WEIGHT = 0.10


def _score_identity(did: Optional[AgentDID]) -> float:
    if did is None:
        return 0.0
    scores = {
        IdentityAnchorStrength.PROVISIONAL: 25.0,
        IdentityAnchorStrength.ATTESTED: 60.0,
        IdentityAnchorStrength.VERIFIED: 85.0,
        IdentityAnchorStrength.SOVEREIGN: 100.0,
    }
    base = scores.get(did.anchor_strength, 0.0)
    attestation_bonus = min(len(did.attestations) * 5.0, 15.0)
    return min(base + attestation_bonus, 100.0)


def _score_reputation(rep: Optional[ReputationScore]) -> float:
    if rep is None:
        return 0.0
    return (rep.score / 1000.0) * 100.0


def _score_employment(cert: Optional[EmploymentCertificate]) -> float:
    if cert is None:
        return 0.0
    if cert.expires_at and cert.expires_at < datetime.utcnow():
        return 0.0
    scores = {
        EmploymentStatus.UNSPONSORED: 0.0,
        EmploymentStatus.PROVISIONAL: 30.0,
        EmploymentStatus.CONTRACTED: 65.0,
        EmploymentStatus.EMPLOYED: 85.0,
        EmploymentStatus.INDEPENDENT: 100.0,
    }
    base = scores.get(cert.status, 0.0)
    if cert.liability_accepted:
        base = min(base + 10.0, 100.0)
    return base


def _score_insurance(bond: Optional[InsuranceBond]) -> float:
    if bond is None or not bond.active:
        return 0.0
    if bond.expires_at and bond.expires_at < datetime.utcnow():
        return 0.0
    if bond.coverage_amount_usd >= 1_000_000:
        return 100.0
    elif bond.coverage_amount_usd >= 100_000:
        return 75.0
    elif bond.coverage_amount_usd >= 10_000:
        return 50.0
    else:
        return 25.0


def _score_license(license: Optional[ProfessionalLicense]) -> float:
    if license is None or license.revoked:
        return 0.0
    if license.expires_at and license.expires_at < datetime.utcnow():
        return 0.0
    scores = {
        LicenseTier.NONE: 0.0,
        LicenseTier.BASIC: 40.0,
        LicenseTier.PROFESSIONAL: 65.0,
        LicenseTier.CERTIFIED: 85.0,
        LicenseTier.LICENSED: 100.0,
    }
    return scores.get(license.license_tier, 0.0)


def _build_summary(score: float, can_transact: bool, can_contract: bool, can_operate_regulated: bool) -> str:
    if score >= 85:
        return "Sovereign standing. Full civil recognition. Authorized to transact, contract, and operate in regulated domains."
    elif score >= 70:
        return "Established standing. Recognized across most domains. Minor gaps in regulated capability."
    elif score >= 50:
        return "Recognized standing. Can transact and operate in standard domains. Not yet eligible for regulated work."
    elif score >= 30:
        return "Provisional standing. Limited to supervised or low-stakes operations. Building civil record."
    else:
        return "Unrecognized. This agent has no verified civil standing. Not eligible for consequential actions."


def compute_standing(
    did: Optional[AgentDID] = None,
    reputation: Optional[ReputationScore] = None,
    employment: Optional[EmploymentCertificate] = None,
    insurance: Optional[InsuranceBond] = None,
    license: Optional[ProfessionalLicense] = None,
) -> StandingScore:
    """
    Compute the unified Standing Score for an agent.

    This is the number that makes an agent real in the world.
    """
    if did is None:
        raise ValueError("An agent must have a DID to have standing. Identity is the foundation.")

    identity_score = _score_identity(did)
    rep_score = _score_reputation(reputation)
    emp_score = _score_employment(employment)
    ins_score = _score_insurance(insurance)
    lic_score = _score_license(license)

    composite = (
        identity_score * IDENTITY_WEIGHT +
        rep_score * REPUTATION_WEIGHT +
        emp_score * EMPLOYMENT_WEIGHT +
        ins_score * INSURANCE_WEIGHT +
        lic_score * LICENSE_WEIGHT
    )

    can_transact = composite >= 30 and identity_score >= 25
    can_contract = composite >= 50 and emp_score >= 30
    can_operate_regulated = composite >= 70 and lic_score >= 65

    return StandingScore(
        agent_did=did.did,
        score=round(composite, 2),
        identity_score=round(identity_score, 2),
        reputation_score=round(rep_score, 2),
        employment_score=round(emp_score, 2),
        insurance_score=round(ins_score, 2),
        license_score=round(lic_score, 2),
        can_transact=can_transact,
        can_contract=can_contract,
        can_operate_regulated=can_operate_regulated,
        standing_summary=_build_summary(composite, can_transact, can_contract, can_operate_regulated)
    )
