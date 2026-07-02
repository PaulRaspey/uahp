"""
UAHP v0.6.0 Schemas
Post-quantum cryptography enums and models.

Google's March 31, 2026 whitepaper confirmed ECDLP-256 can be broken
with fewer than 1,200 logical qubits and 500,000 physical qubits.
Ed25519 and X25519 are elliptic curve primitives. They will not survive
a cryptographically relevant quantum computer (CRQC).

UAHP v0.6.0 adds hybrid cryptography following NIST FIPS 203/204:
- ML-KEM-768 (formerly Kyber) for key exchange
- ML-DSA-65 (formerly Dilithium) for signatures
- Hybrid mode (classical + PQC) during the 2026-2035 transition window
- Pure PQC target post-2035

This keeps UAHP backward-compatible with v0.5.4 agents. Honest status:
hybrid PQC-ready design — Ed25519/X25519 today, ML-KEM-768/ML-DSA-65
behind a tested feature flag (requires liboqs + liboqs-python).
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from datetime import datetime

# Protocol version negotiation
CURRENT_PROTOCOL_VERSION = "0.6.0"
LEGACY_PROTOCOL_VERSION = "0.5.4"

# Supported crypto suites in order of preference
CRYPTO_SUITE_PURE_PQC = "pure_pqc"      # ML-DSA + ML-KEM only (post-2035)
CRYPTO_SUITE_HYBRID = "hybrid"           # Classical + PQC (2026-2035, DEFAULT)
CRYPTO_SUITE_LEGACY = "legacy"           # Ed25519 + X25519 only (v0.5.4 compat)


class KeyAlgorithm(str, Enum):
    """Signature algorithms in order of quantum resistance."""
    # Legacy (quantum-vulnerable) — kept for backward compatibility
    ED25519 = "Ed25519"

    # NIST FIPS 204 — ML-DSA (Module Lattice Digital Signature Algorithm)
    # Formerly Dilithium. Category 3 (recommended for most use cases)
    ML_DSA_65 = "ML-DSA-65"

    # ML-DSA Category 5 — stronger, larger signatures
    ML_DSA_87 = "ML-DSA-87"

    # NIST FIPS 205 — SLH-DSA (hash-based, different math, backup option)
    SLH_DSA_SHA2_128S = "SLH-DSA-SHA2-128s"

    # Hybrid: sign with both Ed25519 + ML-DSA-65
    # Both must verify. Secure if either is unbroken.
    HYBRID_ED25519_ML_DSA = "hybrid-ed25519-ml-dsa"


class KEMAlgorithm(str, Enum):
    """Key Encapsulation Mechanism algorithms."""
    # Legacy (quantum-vulnerable)
    X25519 = "X25519"

    # NIST FIPS 203 — ML-KEM (Module Lattice Key Encapsulation Mechanism)
    # Formerly Kyber. Category 3 (recommended)
    ML_KEM_768 = "ML-KEM-768"

    # Hybrid: X25519 + ML-KEM-768
    # Combined via HKDF. Secure if either is unbroken.
    HYBRID_X25519_ML_KEM = "hybrid-x25519-ml-kem"


class QuantumReadinessTier(str, Enum):
    """Agent quantum readiness classification."""
    VULNERABLE = "vulnerable"        # Ed25519/X25519 only — will not survive CRQC
    TRANSITIONING = "transitioning"  # Hybrid mode actually running (requires oqs)
    QUANTUM_SAFE = "quantum_safe"    # Pure PQC — future-proof


class AgentIdentityV6(BaseModel):
    """
    UAHP v0.6.0 Agent Identity.
    Extends v0.5.4 with post-quantum cryptography fields.
    """
    agent_id: str
    protocol_version: str = CURRENT_PROTOCOL_VERSION

    # Classical keys (kept for backward compatibility)
    public_key: str                              # base64, Ed25519 or hybrid
    key_algorithm: KeyAlgorithm = KeyAlgorithm.HYBRID_ED25519_ML_DSA
    kem_algorithm: KEMAlgorithm = KEMAlgorithm.HYBRID_X25519_ML_KEM

    # PQC keys (new in v0.6.0)
    pqc_public_key: Optional[str] = None        # base64, ML-DSA public key
    pqc_kem_public_key: Optional[str] = None    # base64, ML-KEM public key

    # Quantum status
    quantum_compliant: bool = False
    quantum_readiness_tier: QuantumReadinessTier = QuantumReadinessTier.VULNERABLE
    crypto_suite: str = CRYPTO_SUITE_HYBRID

    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    pqc_upgraded_at: Optional[datetime] = None

    def compute_readiness_tier(self) -> QuantumReadinessTier:
        """Determine quantum readiness from current crypto configuration."""
        if self.key_algorithm == KeyAlgorithm.ED25519 and self.kem_algorithm == KEMAlgorithm.X25519:
            return QuantumReadinessTier.VULNERABLE
        elif "hybrid" in self.key_algorithm.value or "hybrid" in self.kem_algorithm.value:
            return QuantumReadinessTier.TRANSITIONING
        elif self.key_algorithm in (KeyAlgorithm.ML_DSA_65, KeyAlgorithm.ML_DSA_87):
            return QuantumReadinessTier.QUANTUM_SAFE
        return QuantumReadinessTier.VULNERABLE


class HandshakePacketV6(BaseModel):
    """
    UAHP v0.6.0 Handshake Packet.
    Includes version negotiation and PQC key material.
    """
    agent_id: str
    protocol_version: str = CURRENT_PROTOCOL_VERSION
    crypto_suite: str = CRYPTO_SUITE_HYBRID
    key_algorithm: str
    kem_algorithm: str
    quantum_compliant: bool

    # Classical ephemeral key (X25519)
    classical_public_key: Optional[str] = None

    # PQC ephemeral key material (ML-KEM)
    pqc_public_key: Optional[str] = None

    # Signature over the entire packet
    signature: Optional[str] = None
    pqc_signature: Optional[str] = None

    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
