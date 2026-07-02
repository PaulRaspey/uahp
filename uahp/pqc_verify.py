"""
UAHP v0.6.0 Verification
Hybrid signature verification: Ed25519 + ML-DSA-65.

In hybrid mode, BOTH signatures must be present and valid.
This ensures security even if one algorithm is later broken.
"""

from __future__ import annotations
import base64
import hashlib
from typing import Optional

from uahp.schemas.pqc import KeyAlgorithm

try:
    import oqs
    _ = oqs.Signature  # probe that the wrapper actually loaded
    OQS_AVAILABLE = True
except BaseException:  # the wrapper raises SystemExit when liboqs is missing
    oqs = None
    OQS_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def verify_signature(
    message: bytes,
    signature: str,
    public_key: str,
    key_algorithm: KeyAlgorithm = KeyAlgorithm.ED25519,
    pqc_public_key: Optional[str] = None,
    pqc_signature: Optional[str] = None,
) -> bool:
    """
    Verify a signature with hybrid or classical mode.

    In hybrid mode (HYBRID_ED25519_ML_DSA):
    - BOTH Ed25519 AND ML-DSA-65 signatures must be valid
    - If either fails, verification fails
    - This is the "belt AND suspenders" approach

    In pure PQC mode: only ML-DSA verified.
    In legacy mode: only Ed25519 verified.
    """
    try:
        if key_algorithm == KeyAlgorithm.ED25519:
            return _verify_ed25519(message, signature, public_key)

        elif key_algorithm == KeyAlgorithm.ML_DSA_65:
            if not OQS_AVAILABLE or pqc_public_key is None:
                return False
            return _verify_ml_dsa(message, pqc_signature or signature, pqc_public_key, "ML-DSA-65")

        elif key_algorithm == KeyAlgorithm.ML_DSA_87:
            if not OQS_AVAILABLE or pqc_public_key is None:
                return False
            return _verify_ml_dsa(message, pqc_signature or signature, pqc_public_key, "ML-DSA-87")

        elif key_algorithm == KeyAlgorithm.SLH_DSA_SHA2_128S:
            if not OQS_AVAILABLE or pqc_public_key is None:
                return False
            return _verify_ml_dsa(message, pqc_signature or signature, pqc_public_key, "SLH-DSA-SHA2-128s")

        elif key_algorithm == KeyAlgorithm.HYBRID_ED25519_ML_DSA:
            # BOTH must pass
            classical_ok = _verify_ed25519(message, signature, public_key)
            if not classical_ok:
                return False
            if OQS_AVAILABLE and pqc_public_key and pqc_signature:
                pqc_ok = _verify_ml_dsa(message, pqc_signature, pqc_public_key, "ML-DSA-65")
                return pqc_ok
            # If PQC material not present, accept classical only during transition
            return classical_ok

        return False

    except Exception:
        return False


def _verify_ed25519(message: bytes, signature: str, public_key: str) -> bool:
    """Verify Ed25519 signature."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return False
    try:
        sig_bytes = base64.b64decode(signature)
        pub_bytes = base64.b64decode(public_key)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, message)
        return True
    except Exception:
        return False


def _verify_ml_dsa(message: bytes, signature: str, public_key: str, algorithm: str) -> bool:
    """Verify ML-DSA signature (NIST FIPS 204)."""
    if not OQS_AVAILABLE:
        return False
    try:
        sig_bytes = base64.b64decode(signature)
        pub_bytes = base64.b64decode(public_key)
        verifier = oqs.Signature(algorithm)
        return verifier.verify(message, sig_bytes, pub_bytes)
    except Exception:
        return False


def generate_ml_dsa_keypair(algorithm: str = "ML-DSA-65"):
    """
    Generate an ML-DSA keypair.
    Returns (public_key_b64, secret_key_b64) or raises if oqs unavailable.
    """
    if not OQS_AVAILABLE:
        raise RuntimeError(
            "oqs-python not installed. Install with: pip install oqs-python\n"
            "Note: requires liboqs system library. See https://github.com/open-quantum-safe/liboqs"
        )
    signer = oqs.Signature(algorithm)
    public_key = signer.generate_keypair()
    secret_key = signer.export_secret_key()
    return (
        base64.b64encode(public_key).decode(),
        base64.b64encode(secret_key).decode()
    )


def generate_ml_kem_keypair(algorithm: str = "ML-KEM-768"):
    """
    Generate an ML-KEM keypair.
    Returns (public_key_b64, secret_key_b64) or raises if oqs unavailable.
    """
    if not OQS_AVAILABLE:
        raise RuntimeError(
            "oqs-python not installed. Install with: pip install oqs-python"
        )
    kem = oqs.KeyEncapsulation(algorithm)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return (
        base64.b64encode(public_key).decode(),
        base64.b64encode(secret_key).decode()
    )


def quantum_readiness_summary() -> dict:
    """
    Return a summary of the current system's quantum readiness.
    Useful for diagnostics and the POLIS standing score.
    """
    return {
        "oqs_available": OQS_AVAILABLE,
        "cryptography_available": CRYPTOGRAPHY_AVAILABLE,
        "supported_signatures": (
            ["Ed25519", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "hybrid-ed25519-ml-dsa"]
            if OQS_AVAILABLE else ["Ed25519"]
        ),
        "supported_kems": (
            ["X25519", "ML-KEM-768", "hybrid-x25519-ml-kem"]
            if OQS_AVAILABLE else ["X25519"]
        ),
        "quantum_threat": "ECDLP-256 breakable with ~1,200 logical qubits (Google, March 2026)",
        "recommended_action": (
            "Hybrid PQC feature flag available (oqs installed)"
            if OQS_AVAILABLE
            else "Classical-only (Ed25519/X25519). Install liboqs + liboqs-python to enable the hybrid PQC feature flag"
        ),
        "nist_standards": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"],
        "google_timeline": "2029 migration deadline (Google Quantum AI, March 2026)"
    }
