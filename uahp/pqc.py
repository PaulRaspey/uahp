"""
UAHP v0.6.0 SecureSession
Hybrid key exchange: X25519 + ML-KEM-768. Ed25519 (+ ML-DSA-65 when
oqs-python is installed) packet signatures.

Honest security status:
  - The classical path (Ed25519 signatures, X25519 + HKDF key exchange)
    is real, tested, and always on.
  - The PQC path (ML-KEM-768 / ML-DSA-65) runs ONLY when oqs-python is
    installed. If you request a hybrid or pure-PQC suite without oqs,
    construction FAILS LOUDLY — there is no silent downgrade.
  - Every handshake packet carries an explicit `crypto_mode` field so
    both sides know exactly which suite actually ran. Suite mismatches
    are errors, not silent fallbacks.

KEM flow (the part v0.6.0 previously got wrong):
  - The INITIATOR encapsulates to the RESPONDER's ML-KEM public key and
    transmits the resulting ciphertext.
  - The RESPONDER decapsulates the ciphertext with its ML-KEM private key.
  - Both sides then hold the SAME KEM shared secret, which is combined
    with the X25519 shared secret via HKDF (NIST hybrid pattern).

Usage (two processes; packets and ciphertext cross the wire):

    alice = SecureSessionV6(agent_id="alice")   # initiator
    bob   = SecureSessionV6(agent_id="bob")     # responder

    alice_packet = alice.get_handshake_packet()
    bob_packet   = bob.get_handshake_packet()

    ok_a, secret_a, ciphertext = alice.initiate_key_exchange(bob_packet)
    ok_b, secret_b             = bob.complete_key_exchange(alice_packet, ciphertext)

    assert secret_a == secret_b
"""

from __future__ import annotations
import base64
import json
from datetime import datetime
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from uahp.schemas.pqc import (
    KeyAlgorithm, KEMAlgorithm,
    CURRENT_PROTOCOL_VERSION,
    CRYPTO_SUITE_HYBRID, CRYPTO_SUITE_LEGACY, CRYPTO_SUITE_PURE_PQC
)

# Try to import oqs-python (Open Quantum Safe). The wrapper can raise
# RuntimeError (not just ImportError) when the liboqs shared library is
# missing, so guard broadly. Unavailability is NOT silent: requesting a
# PQC suite without a working oqs raises PQCUnavailableError below.
try:
    import oqs
    _ = oqs.KeyEncapsulation  # probe that the wrapper actually loaded
    OQS_AVAILABLE = True
except BaseException:  # the wrapper raises SystemExit when liboqs is missing
    oqs = None
    OQS_AVAILABLE = False

# HKDF info strings — versioned to prevent cross-version attacks
HKDF_INFO_HYBRID = b"UAHP_SESSION_v0.6_HYBRID"
HKDF_INFO_LEGACY = b"UAHP_SESSION_v0.5"
HKDF_INFO_PURE_PQC = b"UAHP_SESSION_v0.6_PQC"

PQC_INSTALL_INSTRUCTIONS = (
    "Post-quantum cryptography was requested but oqs-python is not installed.\n"
    "UAHP will NOT silently fall back to classical crypto.\n"
    "Either:\n"
    "  1. Install the PQC stack:\n"
    "       - Install liboqs (https://github.com/open-quantum-safe/liboqs)\n"
    "       - pip install liboqs-python\n"
    "  2. Or explicitly request the classical suite:\n"
    "       SecureSessionV6(..., key_algorithm=KeyAlgorithm.ED25519,\n"
    "                       kem_algorithm=KEMAlgorithm.X25519)\n"
    "     (classical-only: Ed25519 + X25519; makes no quantum-resistance claim)"
)


class PQCUnavailableError(RuntimeError):
    """Raised when a PQC suite is requested but oqs-python is missing."""


class HandshakeError(Exception):
    """Raised when a handshake packet fails validation."""


def _canonical(packet: Dict, exclude: Tuple[str, ...]) -> bytes:
    return json.dumps(
        {k: v for k, v in packet.items() if k not in exclude},
        sort_keys=True,
    ).encode()


class SecureSessionV6:
    """
    UAHP v0.6.0 Secure Session.

    Classical always: Ed25519 signatures, X25519 key exchange.
    Hybrid (requires oqs-python): + ML-KEM-768 KEM, + ML-DSA-65 signatures.
    """

    def __init__(
        self,
        agent_id: str,
        signing_key: Optional[Ed25519PrivateKey] = None,
        key_algorithm: KeyAlgorithm = KeyAlgorithm.HYBRID_ED25519_ML_DSA,
        kem_algorithm: KEMAlgorithm = KEMAlgorithm.HYBRID_X25519_ML_KEM,
    ):
        self.agent_id = agent_id
        self.key_algorithm = key_algorithm
        self.kem_algorithm = kem_algorithm

        # Real Ed25519 identity key (generated if not supplied)
        self._ed25519_private = signing_key or Ed25519PrivateKey.generate()
        self.public_key = base64.b64encode(
            self._ed25519_private.public_key().public_bytes_raw()
        ).decode()

        self._shared_secret: Optional[bytes] = None
        self._classical_private: Optional[x25519.X25519PrivateKey] = None
        self._kem: Optional[object] = None
        self._kem_public_key: Optional[bytes] = None
        self._ml_dsa: Optional[object] = None
        self._ml_dsa_public_key: Optional[bytes] = None

        # Determine the crypto suite. Requesting PQC without oqs installed
        # is an ERROR, not a warning — no silent downgrade.
        wants_pqc = (
            "hybrid" in kem_algorithm.value
            or kem_algorithm == KEMAlgorithm.ML_KEM_768
            or "hybrid" in key_algorithm.value
            or key_algorithm in (KeyAlgorithm.ML_DSA_65, KeyAlgorithm.ML_DSA_87)
        )
        if wants_pqc and not OQS_AVAILABLE:
            raise PQCUnavailableError(PQC_INSTALL_INSTRUCTIONS)

        if not wants_pqc:
            self.crypto_suite = CRYPTO_SUITE_LEGACY
            self.quantum_compliant = False
        elif "hybrid" in kem_algorithm.value:
            self.crypto_suite = CRYPTO_SUITE_HYBRID
            self.quantum_compliant = True
        else:
            self.crypto_suite = CRYPTO_SUITE_PURE_PQC
            self.quantum_compliant = True

    # ── Packet creation ──────────────────────────────────────────────────

    def get_handshake_packet(self) -> Dict:
        """
        Generate a UAHP v0.6.0 handshake packet.

        Always contains an ephemeral X25519 public key and this agent's
        Ed25519 public key. In hybrid/PQC modes it also contains an
        ML-KEM-768 public key (so the peer can encapsulate to us) and an
        ML-DSA-65 signature. The `crypto_mode` field states exactly
        which suite this session is running.
        """
        self._classical_private = x25519.X25519PrivateKey.generate()
        classical_pub_bytes = self._classical_private.public_key().public_bytes_raw()

        packet = {
            "agent_id": self.agent_id,
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "crypto_suite": self.crypto_suite,
            "crypto_mode": self.crypto_suite,  # what is ACTUALLY running
            "key_algorithm": self.key_algorithm.value,
            "kem_algorithm": self.kem_algorithm.value,
            "quantum_compliant": self.quantum_compliant,
            "public_key": self.public_key,
            "classical_public_key": base64.b64encode(classical_pub_bytes).decode(),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # PQC key material: our ML-KEM public key, so the PEER (as
        # initiator) can encapsulate to us.
        if self.crypto_suite in (CRYPTO_SUITE_HYBRID, CRYPTO_SUITE_PURE_PQC):
            self._kem = oqs.KeyEncapsulation("ML-KEM-768")
            self._kem_public_key = self._kem.generate_keypair()
            packet["pqc_public_key"] = base64.b64encode(self._kem_public_key).decode()

        # Real Ed25519 signature over the canonical packet body.
        packet["signature"] = self._sign_packet(packet)

        # Real ML-DSA-65 signature in hybrid/pure-PQC mode. The ML-DSA
        # public key is added BEFORE signing so the signature covers it.
        if self.crypto_suite in (CRYPTO_SUITE_HYBRID, CRYPTO_SUITE_PURE_PQC):
            if self._ml_dsa is None:
                self._ml_dsa = oqs.Signature("ML-DSA-65")
                self._ml_dsa_public_key = self._ml_dsa.generate_keypair()
            packet["pqc_sig_public_key"] = base64.b64encode(
                self._ml_dsa_public_key
            ).decode()
            packet["pqc_signature"] = self._sign_packet_ml_dsa(packet)

        return packet

    # ── Packet validation ────────────────────────────────────────────────

    def _validate_peer_packet(self, peer_packet: Dict) -> None:
        """
        Verify the peer's packet signature(s) and check that the peer's
        crypto mode matches ours. Mismatches are ERRORS — the protocol
        never silently downgrades to a weaker suite.
        """
        peer_mode = peer_packet.get("crypto_mode", peer_packet.get("crypto_suite"))
        if peer_mode != self.crypto_suite:
            raise HandshakeError(
                f"Crypto mode mismatch: we are running '{self.crypto_suite}', "
                f"peer is running '{peer_mode}'. UAHP does not silently "
                f"downgrade — both sides must explicitly agree on a suite."
            )

        # Verify the peer's Ed25519 signature with the peer's PUBLIC key.
        body = _canonical(peer_packet, exclude=("signature", "pqc_signature", "pqc_sig_public_key"))
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                base64.b64decode(peer_packet["public_key"])
            )
            pub.verify(base64.b64decode(peer_packet["signature"]), body)
        except (KeyError, ValueError, InvalidSignature) as e:
            raise HandshakeError(
                f"Peer packet Ed25519 signature verification FAILED: {e}"
            )

        # In hybrid/pure-PQC mode the ML-DSA signature must ALSO verify.
        if self.crypto_suite in (CRYPTO_SUITE_HYBRID, CRYPTO_SUITE_PURE_PQC):
            try:
                verifier = oqs.Signature("ML-DSA-65")
                ok = verifier.verify(
                    _canonical(peer_packet, exclude=("pqc_signature",)),
                    base64.b64decode(peer_packet["pqc_signature"]),
                    base64.b64decode(peer_packet["pqc_sig_public_key"]),
                )
            except (KeyError, ValueError) as e:
                raise HandshakeError(f"Peer packet ML-DSA signature missing/malformed: {e}")
            if not ok:
                raise HandshakeError("Peer packet ML-DSA-65 signature verification FAILED")

    # ── Key exchange (asymmetric roles — this is the KEM fix) ───────────

    def initiate_key_exchange(
        self, peer_packet: Dict
    ) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """
        INITIATOR role.

        1. Validate the peer's packet (signatures + crypto mode).
        2. X25519 exchange with the peer's ephemeral classical key.
        3. Hybrid/PQC: ENCAPSULATE to the peer's ML-KEM-768 public key,
           producing (ciphertext, kem_shared_secret). The ciphertext MUST
           be transmitted to the peer, who decapsulates it.
        4. HKDF over the concatenated secrets.

        Returns (success, shared_secret, kem_ciphertext_b64).
        kem_ciphertext_b64 is None in legacy mode.
        """
        self._validate_peer_packet(peer_packet)

        if self._classical_private is None:
            raise HandshakeError(
                "Call get_handshake_packet() before initiate_key_exchange() "
                "so the peer has our ephemeral key."
            )

        peer_classical = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_packet["classical_public_key"])
        )
        classical_shared = self._classical_private.exchange(peer_classical)

        if self.crypto_suite == CRYPTO_SUITE_LEGACY:
            self._shared_secret = self._hkdf(classical_shared, HKDF_INFO_LEGACY)
            return True, self._shared_secret, None

        # Encapsulate to the PEER's KEM public key (not our own!).
        # This was the v0.6.0 bug: both sides called encap_secret and
        # derived different secrets. Encapsulation produces a ciphertext
        # for the holder of the KEM PRIVATE key to decapsulate.
        peer_kem_pub = base64.b64decode(peer_packet["pqc_public_key"])
        encapsulator = oqs.KeyEncapsulation("ML-KEM-768")
        ciphertext, kem_shared = encapsulator.encap_secret(peer_kem_pub)

        info = (
            HKDF_INFO_HYBRID
            if self.crypto_suite == CRYPTO_SUITE_HYBRID
            else HKDF_INFO_PURE_PQC
        )
        combined = (
            classical_shared + kem_shared
            if self.crypto_suite == CRYPTO_SUITE_HYBRID
            else kem_shared
        )
        self._shared_secret = self._hkdf(combined, info)
        return True, self._shared_secret, base64.b64encode(ciphertext).decode()

    def complete_key_exchange(
        self, peer_packet: Dict, kem_ciphertext_b64: Optional[str] = None
    ) -> Tuple[bool, Optional[bytes]]:
        """
        RESPONDER role.

        1. Validate the peer's packet (signatures + crypto mode).
        2. X25519 exchange with the peer's ephemeral classical key.
        3. Hybrid/PQC: DECAPSULATE the initiator's ciphertext with our
           ML-KEM-768 private key, recovering the same kem_shared_secret
           the initiator produced during encapsulation.
        4. HKDF over the concatenated secrets — both sides now match.

        Returns (success, shared_secret).
        """
        self._validate_peer_packet(peer_packet)

        if self._classical_private is None:
            raise HandshakeError(
                "Call get_handshake_packet() before complete_key_exchange() "
                "so the peer has our ephemeral key."
            )

        peer_classical = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_packet["classical_public_key"])
        )
        classical_shared = self._classical_private.exchange(peer_classical)

        if self.crypto_suite == CRYPTO_SUITE_LEGACY:
            self._shared_secret = self._hkdf(classical_shared, HKDF_INFO_LEGACY)
            return True, self._shared_secret

        if kem_ciphertext_b64 is None:
            raise HandshakeError(
                f"{self.crypto_suite} mode requires the initiator's KEM "
                "ciphertext. Legacy mode was not negotiated — refusing to "
                "downgrade silently."
            )
        if self._kem is None:
            raise HandshakeError(
                "No ML-KEM keypair; call get_handshake_packet() first."
            )

        # Decapsulate with OUR private key — recovers the initiator's secret.
        kem_shared = self._kem.decap_secret(base64.b64decode(kem_ciphertext_b64))

        info = (
            HKDF_INFO_HYBRID
            if self.crypto_suite == CRYPTO_SUITE_HYBRID
            else HKDF_INFO_PURE_PQC
        )
        combined = (
            classical_shared + kem_shared
            if self.crypto_suite == CRYPTO_SUITE_HYBRID
            else kem_shared
        )
        self._shared_secret = self._hkdf(combined, info)
        return True, self._shared_secret

    def derive_shared_secret(self, peer_packet: Dict) -> Tuple[bool, Optional[bytes]]:
        """
        Legacy v0.5.4-compatible symmetric derivation (X25519 only).
        Only valid when BOTH sides explicitly run the legacy suite.
        Hybrid/PQC sessions must use initiate_key_exchange /
        complete_key_exchange, which have distinct encap/decap roles.
        """
        if self.crypto_suite != CRYPTO_SUITE_LEGACY:
            raise HandshakeError(
                "derive_shared_secret() is legacy-only. Hybrid/PQC key "
                "exchange is asymmetric: use initiate_key_exchange() on one "
                "side and complete_key_exchange() on the other."
            )
        self._validate_peer_packet(peer_packet)
        if self._classical_private is None:
            self._classical_private = x25519.X25519PrivateKey.generate()
        peer_classical = x25519.X25519PublicKey.from_public_bytes(
            base64.b64decode(peer_packet["classical_public_key"])
        )
        raw_shared = self._classical_private.exchange(peer_classical)
        self._shared_secret = self._hkdf(raw_shared, HKDF_INFO_LEGACY)
        return True, self._shared_secret

    # ── Signing ──────────────────────────────────────────────────────────

    def _sign_packet(self, packet: Dict) -> str:
        """Real Ed25519 signature over the canonical packet body."""
        body = _canonical(packet, exclude=("signature", "pqc_signature", "pqc_sig_public_key"))
        return base64.b64encode(self._ed25519_private.sign(body)).decode()

    def _sign_packet_ml_dsa(self, packet: Dict) -> str:
        """
        Real ML-DSA-65 signature (NIST FIPS 204). Only callable in
        hybrid/pure-PQC mode, which requires oqs — no stub, no fallback.
        The signed body includes pqc_sig_public_key and the Ed25519
        signature, excluding only the ML-DSA signature itself.
        """
        body = _canonical(packet, exclude=("pqc_signature",))
        return base64.b64encode(self._ml_dsa.sign(body)).decode()

    @staticmethod
    def _hkdf(secret_material: bytes, info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        ).derive(secret_material)

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def shared_secret(self) -> Optional[bytes]:
        return self._shared_secret

    @property
    def shared_secret_hex(self) -> Optional[str]:
        return self._shared_secret.hex() if self._shared_secret else None
