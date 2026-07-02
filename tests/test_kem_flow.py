"""
UAHP v0.6.0 KEM Flow Test
==========================
Proves the fix for the v0.6.0 KEM bug (both sides called encap_secret
and derived DIFFERENT secrets; the bug was masked by a silent classical
fallback that made demos "pass").

What this suite asserts:

  [A] Classical path (always runs):
      - Legacy sessions derive EQUAL secrets via real X25519 + HKDF.
      - Packet Ed25519 signatures are real and tamper-evident.
      - Requesting a hybrid/PQC suite without oqs-python FAILS LOUDLY
        (PQCUnavailableError), never silently downgrades.
      - crypto_mode mismatch between peers is a hard error.

  [B] Hybrid encap/decap flow:
      - If oqs-python IS installed: runs against REAL ML-KEM-768 and
        asserts initiator.secret == responder.secret.
      - If oqs-python is NOT installed: runs the same code path against
        a clearly-labeled FAKE in-memory KEM to prove the protocol
        wiring (initiator encapsulates -> ciphertext crosses the wire ->
        responder decapsulates -> equal secrets). The fake KEM is NOT
        cryptography; it exists so the flow logic is testable anywhere.
        The test prints which mode it ran in.

Run: python3 test_kem_flow.py
"""

import os
import sys
import importlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}")


# ── Fake oqs (flow testing only — NOT cryptography) ─────────────────────────

class _FakeKEM:
    """XOR-based stand-in for ML-KEM-768. Flow testing ONLY."""
    def __init__(self, alg):
        self._priv = None

    def generate_keypair(self):
        self._priv = os.urandom(32)
        return b"FAKEKEMPUB" + self._priv  # embeds priv: obviously not secure

    def encap_secret(self, peer_pub):
        peer_priv = peer_pub[len(b"FAKEKEMPUB"):]
        secret = os.urandom(32)
        ciphertext = bytes(a ^ b for a, b in zip(secret, peer_priv))
        return ciphertext, secret

    def decap_secret(self, ciphertext):
        return bytes(a ^ b for a, b in zip(ciphertext, self._priv))


class _FakeSignature:
    """Hash-based stand-in for ML-DSA-65. Flow testing ONLY."""
    def __init__(self, alg):
        self._key = None

    def generate_keypair(self):
        self._key = os.urandom(32)
        return b"FAKESIGPUB" + self._key

    def sign(self, message):
        import hashlib
        return hashlib.sha256(self._key + message).digest()

    def verify(self, message, signature, public_key):
        import hashlib
        key = public_key[len(b"FAKESIGPUB"):]
        return hashlib.sha256(key + message).digest() == signature


class _FakeOQS:
    KeyEncapsulation = _FakeKEM
    Signature = _FakeSignature


# ── Tests ────────────────────────────────────────────────────────────────────

def test_classical_path(sv6):
    print("\n[A1] Legacy X25519 path — equal secrets")
    alice = sv6.SecureSessionV6(
        "alice", key_algorithm=sv6.KeyAlgorithm.ED25519,
        kem_algorithm=sv6.KEMAlgorithm.X25519)
    bob = sv6.SecureSessionV6(
        "bob", key_algorithm=sv6.KeyAlgorithm.ED25519,
        kem_algorithm=sv6.KEMAlgorithm.X25519)

    pa, pb = alice.get_handshake_packet(), bob.get_handshake_packet()
    check("crypto_mode is explicit in packet", pa["crypto_mode"] == "legacy")

    ok_a, secret_a, ct = alice.initiate_key_exchange(pb)
    ok_b, secret_b = bob.complete_key_exchange(pa, ct)
    check("both sides succeed", ok_a and ok_b)
    check("no KEM ciphertext in legacy mode", ct is None)
    check("secrets are EQUAL", secret_a == secret_b and len(secret_a) == 32)

    print("\n[A2] Packet signatures are real Ed25519")
    tampered = dict(pb)
    tampered["agent_id"] = "evil-bob"
    try:
        alice2 = sv6.SecureSessionV6(
            "alice2", key_algorithm=sv6.KeyAlgorithm.ED25519,
            kem_algorithm=sv6.KEMAlgorithm.X25519)
        alice2.get_handshake_packet()
        alice2.initiate_key_exchange(tampered)
        check("tampered packet rejected", False)
    except sv6.HandshakeError:
        check("tampered packet rejected", True)


def test_fail_loudly_without_oqs(sv6):
    print("\n[A3] No silent fallback")
    if sv6.OQS_AVAILABLE:
        print("  SKIP  oqs is installed; fail-loudly path not reachable here")
        return
    try:
        sv6.SecureSessionV6("alice")  # default is hybrid
        check("hybrid without oqs raises PQCUnavailableError", False)
    except sv6.PQCUnavailableError as e:
        check("hybrid without oqs raises PQCUnavailableError", True)
        check("error message includes install instructions",
              "liboqs" in str(e) and "silently" in str(e))


def test_mode_mismatch_rejected(sv6):
    print("\n[A4] Crypto mode mismatch is a hard error")
    alice = sv6.SecureSessionV6(
        "alice", key_algorithm=sv6.KeyAlgorithm.ED25519,
        kem_algorithm=sv6.KEMAlgorithm.X25519)
    alice.get_handshake_packet()
    fake_hybrid_packet = {
        "agent_id": "bob", "crypto_mode": "hybrid", "crypto_suite": "hybrid",
        "public_key": "AA==", "signature": "AA==",
        "classical_public_key": "AA==",
    }
    try:
        alice.initiate_key_exchange(fake_hybrid_packet)
        check("legacy peer rejects hybrid packet", False)
    except sv6.HandshakeError as e:
        check("legacy peer rejects hybrid packet", "mismatch" in str(e).lower())


def test_hybrid_encap_decap(sv6, real_oqs: bool):
    label = "REAL ML-KEM-768 (oqs installed)" if real_oqs \
        else "FAKE in-memory KEM (flow wiring only — install oqs for real PQC)"
    print(f"\n[B] Hybrid encap/decap flow — {label}")

    alice = sv6.SecureSessionV6("alice")  # initiator, hybrid default
    bob = sv6.SecureSessionV6("bob")      # responder, hybrid default

    pa, pb = alice.get_handshake_packet(), bob.get_handshake_packet()
    check("hybrid packets carry ML-KEM public key",
          "pqc_public_key" in pa and "pqc_public_key" in pb)
    check("hybrid packets carry ML-DSA signature",
          "pqc_signature" in pa and "pqc_sig_public_key" in pa)
    check("crypto_mode is explicit", pa["crypto_mode"] == "hybrid")

    # Initiator encapsulates to RESPONDER's KEM public key.
    ok_a, secret_a, ciphertext = alice.initiate_key_exchange(pb)
    check("initiator produced ciphertext for the wire", ciphertext is not None)

    # Responder decapsulates with its own KEM private key.
    ok_b, secret_b = bob.complete_key_exchange(pa, ciphertext)

    check("both sides succeed", ok_a and ok_b)
    check("SECRETS ARE EQUAL (the v0.6.0 bug is fixed)",
          secret_a == secret_b and len(secret_a) == 32)

    # Responder must refuse to proceed without the ciphertext.
    bob2 = sv6.SecureSessionV6("bob2")
    bob2.get_handshake_packet()
    try:
        bob2.complete_key_exchange(pa, None)
        check("responder refuses hybrid exchange without ciphertext", False)
    except sv6.HandshakeError:
        check("responder refuses hybrid exchange without ciphertext", True)


if __name__ == "__main__":
    print("UAHP v0.6.0 KEM Flow Test")
    print("=" * 60)

    import uahp.pqc as sv6
    real_oqs = sv6.OQS_AVAILABLE

    test_classical_path(sv6)
    test_fail_loudly_without_oqs(sv6)
    test_mode_mismatch_rejected(sv6)

    if not real_oqs:
        # Inject the fake KEM and reload so the hybrid FLOW is testable.
        sys.modules["oqs"] = _FakeOQS()
        sv6 = importlib.reload(sv6)
    test_hybrid_encap_decap(sv6, real_oqs)

    print("\n" + "=" * 60)
    print(f"{PASS} passed, {FAIL} failed"
          + ("" if real_oqs else "  (hybrid tested against FAKE KEM; "
             "install liboqs + liboqs-python to test real ML-KEM-768)"))
    sys.exit(1 if FAIL else 0)
