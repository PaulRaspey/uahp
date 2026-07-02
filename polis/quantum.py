"""
POLIS Quantum Readiness Module
Integrates quantum compliance into the civil Standing Score.

An agent that cannot protect its communications is not a trustworthy
civil actor. Quantum readiness is now a component of civil standing.

Weighting rationale:
- Identity (25%): unchanged — DID anchoring is not crypto-dependent
- Reputation (30%): unchanged — liveness history is behavioral
- Employment (20%): unchanged — sponsorship chain is legal
- Insurance (15%): unchanged — bond coverage is financial
- License (10%): split 5% license + 5% quantum readiness

As quantum threats mature toward 2029, these weights will shift.
By v1.0 (post-2035), quantum_safe will be a hard requirement
for can_contract and can_operate_regulated.
"""

from __future__ import annotations
from typing import Dict, Optional
from datetime import datetime


class QuantumReadinessScore:
    """
    Computes the quantum readiness component of the POLIS Standing Score.
    Currently weighted at 5% of total standing.
    Will increase to 15% in POLIS v0.2.0 (Q3 2026).
    Will be a hard requirement in POLIS v1.0.0 (post-2035).
    """

    WEIGHT_CURRENT = 0.05       # v0.1.0 — 5% of Standing Score
    WEIGHT_2026 = 0.10          # v0.2.0 — 10% (planned Q3 2026)
    WEIGHT_2029 = 0.20          # v0.3.0 — 20% (Google's migration deadline)
    WEIGHT_POST_2035 = 1.0      # v1.0.0 — hard requirement

    @staticmethod
    def score(
        crypto_suite: str = "legacy",
        key_algorithm: str = "Ed25519",
        kem_algorithm: str = "X25519",
        quantum_compliant: bool = False,
        pqc_upgraded_at: Optional[datetime] = None,
    ) -> float:
        """
        Compute quantum readiness score from 0.0 to 100.0.

        Tier mapping:
        - vulnerable (legacy Ed25519/X25519): 10.0 — partial credit during transition
        - transitioning (hybrid mode): 75.0 — good for 2026-2029 window
        - quantum_safe (pure PQC): 100.0 — future-proof

        Partial credit for vulnerable agents exists because:
        CRQCs are not yet deployed. Legacy agents are not yet broken.
        But the clock is running. Google's timeline says 2029.
        """
        if crypto_suite == "pure_pqc":
            base = 100.0
        elif crypto_suite == "hybrid":
            base = 75.0
            # Bonus for early adoption
            if pqc_upgraded_at is not None:
                days_since_upgrade = (datetime.utcnow() - pqc_upgraded_at).days
                if days_since_upgrade < 30:
                    base = min(base + 10.0, 100.0)  # Early adopter bonus
        elif crypto_suite == "legacy":
            base = 10.0
        else:
            base = 0.0

        # Algorithm-level adjustments
        if "ML-DSA" in key_algorithm and "ML-KEM" in kem_algorithm:
            base = min(base + 5.0, 100.0)
        elif "hybrid" in key_algorithm.lower() and "hybrid" in kem_algorithm.lower():
            base = min(base + 2.5, 100.0)

        return round(base, 2)

    @staticmethod
    def standing_label(score: float) -> str:
        if score >= 90:
            return "Quantum Sovereign"
        elif score >= 70:
            return "Quantum Transitioning"
        elif score >= 10:
            return "Quantum Vulnerable (Legacy)"
        else:
            return "Quantum Unknown"

    @staticmethod
    def threat_advisory(crypto_suite: str = "legacy") -> str:
        if crypto_suite == "legacy":
            return (
                "WARNING: This agent uses Ed25519/X25519 cryptography. "
                "Google's March 2026 whitepaper confirmed ECDLP-256 can be broken "
                "with ~1,200 logical qubits / 500,000 physical qubits. "
                "Upgrade to hybrid mode (ML-DSA + ML-KEM) before 2029. "
                "Install oqs-python and upgrade to UAHP v0.6.0."
            )
        elif crypto_suite == "hybrid":
            return (
                "TRANSITIONING: Hybrid mode active. "
                "Classical + ML-KEM-768 + ML-DSA-65. "
                "Secure against current and near-future quantum threats. "
                "Monitor NIST guidance for pure-PQC transition timeline."
            )
        else:
            return "QUANTUM SAFE: Pure PQC mode. No elliptic curve primitives in use."


def inject_quantum_into_standing(standing_dict: Dict, agent_identity: Dict) -> Dict:
    """
    Inject quantum readiness into an existing POLIS Standing Score dict.
    Call this after computing the base Standing Score.
    """
    crypto_suite = agent_identity.get("crypto_suite", "legacy")
    key_algorithm = agent_identity.get("key_algorithm", "Ed25519")
    kem_algorithm = agent_identity.get("kem_algorithm", "X25519")
    quantum_compliant = agent_identity.get("quantum_compliant", False)
    pqc_upgraded_at = agent_identity.get("pqc_upgraded_at")

    if isinstance(pqc_upgraded_at, str):
        try:
            pqc_upgraded_at = datetime.fromisoformat(pqc_upgraded_at)
        except Exception:
            pqc_upgraded_at = None

    q_score = QuantumReadinessScore.score(
        crypto_suite=crypto_suite,
        key_algorithm=key_algorithm,
        kem_algorithm=kem_algorithm,
        quantum_compliant=quantum_compliant,
        pqc_upgraded_at=pqc_upgraded_at,
    )

    standing_dict["quantum_readiness_score"] = q_score
    standing_dict["quantum_readiness_label"] = QuantumReadinessScore.standing_label(q_score)
    standing_dict["quantum_threat_advisory"] = QuantumReadinessScore.threat_advisory(crypto_suite)

    # Adjust overall score (5% weight currently)
    current_score = standing_dict.get("score", 0.0)
    standing_dict["score"] = round(
        (current_score * 0.95) + (q_score * QuantumReadinessScore.WEIGHT_CURRENT),
        2
    )

    # Future: hard gate for regulated operations
    if crypto_suite == "legacy" and standing_dict.get("can_operate_regulated", False):
        standing_dict["can_operate_regulated_note"] = (
            "Warning: Regulatory domains may require quantum-safe cryptography by 2029. "
            "Upgrade to hybrid mode to maintain regulated status."
        )

    return standing_dict
