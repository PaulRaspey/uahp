"""
UAHP v0.6.0 Production Hardening Demo
Shows three real production problem solutions:
1. Sliding window for out-of-order packet handling
2. Payload fragmentation for MTU-constrained transports
3. Delegated ML-DSA verification for constrained edge devices
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.signing_policy import (
    SessionCache, FragmentAssembler, DelegatedVerifier,
    MTU_CONSERVATIVE, MTU_CONSTRAINED
)


def demo_sliding_window():
    print("=" * 65)
    print("FIX 1: Sliding Window Sequence Numbers")
    print("Handles out-of-order delivery in async agent networks")
    print("=" * 65)
    print()

    cache = SessionCache(
        session_id="session_alice_bob",
        shared_secret=b"shared_secret_32bytes_padding___"
    )

    # Alice sends 6 messages
    sigs = {}
    for i in range(1, 7):
        sig, seq = cache.sign_in_session(f"message {i}".encode())
        sigs[seq] = sig

    print("  Alice sends messages 1-6.")
    print("  Bob receives them out of order: 1, 2, 5, 4, 3, 6")
    print()

    receive_cache = SessionCache(
        session_id="session_alice_bob",
        shared_secret=b"shared_secret_32bytes_padding___"
    )

    out_of_order = [1, 2, 5, 4, 3, 6]
    for seq in out_of_order:
        valid, reason = receive_cache.verify_in_session(
            f"message {seq}".encode(), sigs[seq], seq
        )
        status = "✓ accepted" if valid else f"✗ rejected ({reason})"
        print(f"  Seq {seq}: {status}")

    print()
    print("  Replay attack test — resend message 3:")
    valid, reason = receive_cache.verify_in_session(
        b"message 3", sigs[3], 3
    )
    print(f"  Seq 3 (replay): {'✓ accepted' if valid else f'✗ rejected ({reason})'}")
    print()


def demo_fragmentation():
    print("=" * 65)
    print("FIX 2: Payload Fragmentation for MTU-Constrained Transports")
    print("ML-DSA-87 signatures are ~4.6KB — handles edge/IoT networks")
    print("=" * 65)
    print()

    assembler = FragmentAssembler()

    # Simulate a death certificate with a large ML-DSA-87 signature
    death_cert_payload = b"agent_xyz:dead:" + b"A" * 200  # Simulated payload
    ml_dsa_signature = b"S" * 4600  # Simulated 4.6KB ML-DSA-87 signature
    full_message = death_cert_payload + ml_dsa_signature

    print(f"  Full death certificate size: {len(full_message):,} bytes")
    print(f"  Standard MTU: {MTU_CONSERVATIVE} bytes")
    print(f"  Needs fragmentation: {assembler.should_fragment(full_message, MTU_CONSERVATIVE)}")
    print(f"  Constrained MTU (LoRaWAN): {MTU_CONSTRAINED} bytes")
    print()

    # Fragment for constrained transport
    fragments = assembler.fragment(full_message, "death_cert_001", MTU_CONSTRAINED)
    print(f"  Fragmented into {len(fragments)} chunks for constrained transport")
    for f in fragments[:3]:
        print(f"  Fragment {f['fragment_index']}/{f['fragment_total']-1}: {f['size_bytes']} bytes")
    if len(fragments) > 3:
        print(f"  ... {len(fragments) - 3} more fragments")
    print()

    # Reassemble — simulate out-of-order arrival
    import random
    shuffled = fragments.copy()
    random.shuffle(shuffled)
    print(f"  Reassembling {len(shuffled)} fragments (shuffled order)...")

    recv_assembler = FragmentAssembler()
    result = None
    for frag in shuffled:
        complete, payload = recv_assembler.receive_fragment(frag)
        if complete:
            result = payload
            break

    if result:
        print(f"  Reassembled: {len(result):,} bytes")
        print(f"  Integrity check: {'✓ passed' if result == full_message else '✗ failed'}")
    print()


def demo_delegated_verification():
    print("=" * 65)
    print("FIX 3: Delegated ML-DSA Verification for Edge Devices")
    print("Constrained agents (drones, sensors) delegate heavy crypto")
    print("=" * 65)
    print()

    # Constrained agent — a drone with limited compute
    drone = DelegatedVerifier(
        trusted_verifier_ids=["registry_node_alpha", "gateway_node_beta"],
        local_agent_id="drone_sensor_007"
    )

    # Simulate receiving a death certificate with ML-DSA-87 signature
    message = b"agent_xyz confirmed dead - signed by authority"
    signature = "ml_dsa_87_signature_stub_" + "x" * 100
    signer_pubkey = "authority_ml_dsa_public_key_base64"

    print("  Drone receives death certificate with ML-DSA-87 signature.")
    print(f"  Drone compute: insufficient for ML-DSA-87 verification")
    print()

    # Drone builds a verification request
    request = drone.build_verification_request(
        message=message,
        signature=signature,
        signer_public_key=signer_pubkey,
        algorithm="ML-DSA-87"
    )
    print(f"  Drone sends verification request to registry_node_alpha")
    print(f"  Request ID: {request['request_id']}")
    print(f"  Message hash: {request['message_hash'][:32]}...")
    print()

    # Heavy registry node runs the actual ML-DSA-87 verification
    # and builds an attestation signed with its REAL Ed25519 key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    attester_private_key = Ed25519PrivateKey.generate()
    attester_public_key = attester_private_key.public_key().public_bytes_raw().hex()

    attestation = drone.build_attestation(
        request=request,
        verification_result=True,  # Registry ran ML-DSA-87 and it passed
        attester_id="registry_node_alpha",
        attester_private_key=attester_private_key
    )

    print(f"  Registry node runs ML-DSA-87 verification...")
    print(f"  Registry sends signed attestation back to drone")
    print()

    # Drone validates the attestation with lightweight Ed25519
    valid, reason = drone.receive_attestation(
        attestation=attestation,
        attester_public_key=attester_public_key
    )

    print(f"  Drone validates attestation (Ed25519 — lightweight):")
    print(f"  Result: {'✓ ' + reason if valid else '✗ ' + reason}")
    print()

    # Test: untrusted attester
    drone2 = DelegatedVerifier(
        trusted_verifier_ids=["registry_node_alpha"],
        local_agent_id="drone_sensor_008"
    )
    request2 = drone2.build_verification_request(message, signature, signer_pubkey)
    rogue_key = Ed25519PrivateKey.generate()
    fake_attestation = drone2.build_attestation(
        request=request2,
        verification_result=True,
        attester_id="unknown_rogue_node",  # Not trusted
        attester_private_key=rogue_key
    )
    valid2, reason2 = drone2.receive_attestation(
        fake_attestation, rogue_key.public_key().public_bytes_raw().hex()
    )
    print(f"  Rogue attester test: {'✓ accepted' if valid2 else f'✗ rejected ({reason2})'}")
    print()


if __name__ == "__main__":
    print()
    print("UAHP v0.6.0 — Production Hardening: Three Real Problems Solved")
    print()
    demo_sliding_window()
    demo_fragmentation()
    demo_delegated_verification()

    print("=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print()
    print("  Problem 1: Out-of-order packets break HMAC sequence")
    print("  Solution:  Sliding window (size=32) + replay bitmap")
    print()
    print("  Problem 2: ML-DSA-87 + large payload exceeds MTU")
    print("  Solution:  UAHP-level fragmentation with integrity check")
    print()
    print("  Problem 3: Edge devices can't run ML-DSA-87 locally")
    print("  Solution:  Delegated verification with bound attestation")
    print("             Constrained agent verifies attestation with")
    print("             lightweight Ed25519 — not the ML-DSA signature")
    print()
    print("  All three solutions follow established protocol patterns:")
    print("  TCP sliding window / IP fragmentation / OCSP delegation")
    print("  Applied to the agentic trust layer for the first time.")
