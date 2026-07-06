"""
UAHP v0.6.0 Demo: Hybrid Handshake (X25519 + ML-KEM-768)
=========================================================
Shows the full handshake between two agents with distinct
initiator/responder roles.

If oqs-python is installed:  hybrid mode (classical + real ML-KEM-768).
If not: this demo EXPLICITLY selects the classical suite and says so.
There is no silent fallback — requesting hybrid without oqs raises.

Run: python3 demo_pqc_handshake.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.pqc import SecureSessionV6, OQS_AVAILABLE
from uahp.schemas.pqc import KeyAlgorithm, KEMAlgorithm
from uahp.pqc_verify import quantum_readiness_summary
from polis.quantum import QuantumReadinessScore


def run_demo():
    print("=" * 65)
    print("UAHP v0.6.0 — Hybrid Handshake Demo")
    print("=" * 65)
    print()

    # Show quantum readiness of this system
    summary = quantum_readiness_summary()
    print("SYSTEM PQC STATUS:")
    print(f"  oqs-python available: {summary['oqs_available']}")
    print(f"  Supported KEMs: {', '.join(summary['supported_kems'])}")
    print(f"  Supported signatures: {', '.join(summary['supported_signatures'][:3])}...")
    print()

    # Choose the crypto suite EXPLICITLY. No silent downgrades.
    if OQS_AVAILABLE:
        suite_kwargs = dict(
            key_algorithm=KeyAlgorithm.HYBRID_ED25519_ML_DSA,
            kem_algorithm=KEMAlgorithm.HYBRID_X25519_ML_KEM,
        )
        print("SUITE: hybrid (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65)")
    else:
        suite_kwargs = dict(
            key_algorithm=KeyAlgorithm.ED25519,
            kem_algorithm=KEMAlgorithm.X25519,
        )
        print("SUITE: classical-only (Ed25519 + X25519)")
        print("  NOTE: oqs-python is not installed, so this demo explicitly")
        print("  selects the classical suite. This configuration makes NO")
        print("  quantum-resistance claim. To run the hybrid PQC suite:")
        print("    1. install liboqs (github.com/open-quantum-safe/liboqs)")
        print("    2. pip install liboqs-python")
    print()

    # Create two agents — real Ed25519 keys are generated internally.
    print("CREATING AGENTS...")
    alice = SecureSessionV6(agent_id="alice", **suite_kwargs)   # initiator
    bob = SecureSessionV6(agent_id="bob", **suite_kwargs)       # responder
    print(f"  Alice crypto suite: {alice.crypto_suite}")
    print(f"  Bob crypto suite:   {bob.crypto_suite}")
    print(f"  Alice Ed25519 public key: {alice.public_key[:24]}...")
    print()

    # Exchange handshake packets (these cross the wire).
    print("HANDSHAKE PACKET EXCHANGE...")
    alice_packet = alice.get_handshake_packet()
    bob_packet = bob.get_handshake_packet()
    print(f"  Packet fields: {sorted(alice_packet.keys())}")
    print(f"  crypto_mode (what actually runs): {alice_packet['crypto_mode']}")
    print(f"  Ed25519 signature present: {'signature' in alice_packet}")
    print(f"  ML-KEM public key present: {'pqc_public_key' in alice_packet}")
    print()

    # Key exchange with distinct roles:
    #   initiator ENCAPSULATES to the responder's ML-KEM public key,
    #   responder DECAPSULATES the transmitted ciphertext.
    print("KEY EXCHANGE (initiator encapsulates, responder decapsulates)...")
    ok_a, secret_a, kem_ciphertext = alice.initiate_key_exchange(bob_packet)
    ok_b, secret_b = bob.complete_key_exchange(alice_packet, kem_ciphertext)

    print(f"  Initiator (Alice) success: {ok_a}")
    print(f"  Responder (Bob) success:   {ok_b}")
    if kem_ciphertext:
        print(f"  KEM ciphertext transmitted: {len(kem_ciphertext)} bytes (b64)")
    print(f"  Secrets match: {secret_a == secret_b}")
    print(f"  Shared secret: {secret_a.hex()[:32]}...")
    print()

    # POLIS quantum standing
    print("POLIS QUANTUM STANDING...")
    q_score = QuantumReadinessScore.score(
        crypto_suite=alice.crypto_suite,
        key_algorithm=alice.key_algorithm.value,
        kem_algorithm=alice.kem_algorithm.value,
        quantum_compliant=alice.quantum_compliant,
    )
    print(f"  Quantum readiness score: {q_score} / 100")
    print(f"  Label: {QuantumReadinessScore.standing_label(q_score)}")
    print()

    print("=" * 65)
    print("SUMMARY")
    print("=" * 65)
    if alice.quantum_compliant:
        print("  Suite: HYBRID — X25519 + ML-KEM-768, Ed25519 + ML-DSA-65")
        print("  Both classical AND PQC must be broken to recover the secret.")
    else:
        print("  Suite: CLASSICAL — Ed25519 + X25519 (real, tested crypto).")
        print("  No quantum-resistance claim. Hybrid PQC (ML-KEM-768/ML-DSA-65)")
        print("  is available behind a tested feature flag when oqs-python")
        print("  is installed.")


if __name__ == "__main__":
    run_demo()
