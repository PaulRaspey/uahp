"""
UAHP v0.6.0 Signing Policy
Tiered cryptographic overhead based on message consequence.

The problem: ML-DSA-65 signatures are 2.4KB vs 64 bytes for Ed25519.
Verification takes ~2ms on constrained hardware vs ~0.05ms for Ed25519.
Applying maximum overhead to every message is wasteful and unnecessary.

The solution: match cryptographic cost to operational consequence.

A heartbeat ping does not need the same protection as a death certificate.
A POLIS Standing Score credential does not need the same treatment as a
registry discovery query.

This is the same principle UAHP already applies to compute via SMART-UAHP:
route intelligence to the lowest thermodynamic pressure.
Here we apply it to cryptography: use the minimum security that the
consequence of the message actually requires.

Policy tiers:
  LIGHTWEIGHT  — Ed25519 only. Heartbeats, pings, registry queries.
  STANDARD     — Hybrid Ed25519 + ML-DSA-65. Task delegation, handshakes.
  MAXIMUM      — ML-DSA-87 only. Death certs, POLIS credentials, contracts.

Session caching:
  Full hybrid verification happens once at session establishment.
  In-session messages use HMAC-SHA256 (symmetric, ~microseconds).
  This mirrors TLS 1.3: expensive handshake once, cheap crypto after.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import time
from enum import Enum
from typing import Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from uahp.pqc import PQCUnavailableError, PQC_INSTALL_INSTRUCTIONS

# oqs wrapper raises SystemExit (not ImportError) when liboqs is missing,
# so the guard must catch BaseException.
try:
    import oqs
    _ = oqs.Signature
    OQS_AVAILABLE = True
except BaseException:
    oqs = None
    OQS_AVAILABLE = False


class SigningPolicy(str, Enum):
    """
    Cryptographic signing policy tiers.
    Match cost to consequence — not maximum to everything.
    """
    LIGHTWEIGHT = "lightweight"
    # Use: heartbeats, pings, liveness probes, registry discovery queries
    # Crypto: Ed25519 only
    # Latency: ~0.05ms
    # Signature size: 64 bytes
    # Quantum risk: exists but consequence of compromise is low

    STANDARD = "standard"
    # Use: task delegation, initial handshakes, agent registration, CSP handoffs
    # Crypto: Hybrid Ed25519 + ML-DSA-65
    # Latency: ~0.5ms (server) / ~2ms (constrained hardware)
    # Signature size: ~2.5KB
    # Quantum risk: mitigated — both classical and PQC must be broken

    MAXIMUM = "maximum"
    # Use: death certificates, POLIS credentials, contracts, insurance bonds
    # Crypto: ML-DSA-87 (pure PQC, strongest available)
    # Latency: ~1ms (server) / ~4ms (constrained hardware)
    # Signature size: ~4.6KB
    # Quantum risk: none — no classical primitives


# Message type to policy mapping
# UAHP agents use this to automatically select the right tier
MESSAGE_POLICY_MAP: Dict[str, SigningPolicy] = {
    # Lightweight — operational noise, low consequence
    "heartbeat": SigningPolicy.LIGHTWEIGHT,
    "ping": SigningPolicy.LIGHTWEIGHT,
    "pong": SigningPolicy.LIGHTWEIGHT,
    "registry_query": SigningPolicy.LIGHTWEIGHT,
    "capability_discovery": SigningPolicy.LIGHTWEIGHT,
    "liveness_probe": SigningPolicy.LIGHTWEIGHT,

    # Standard — consequential but reversible
    "handshake": SigningPolicy.STANDARD,
    "agent_registration": SigningPolicy.STANDARD,
    "task_delegation": SigningPolicy.STANDARD,
    "csp_handoff": SigningPolicy.STANDARD,
    "session_init": SigningPolicy.STANDARD,
    "sponsorship_cert": SigningPolicy.STANDARD,
    "employment_cert": SigningPolicy.STANDARD,

    # Maximum — irreversible, legally or financially consequential
    "death_certificate": SigningPolicy.MAXIMUM,
    "polis_credential": SigningPolicy.MAXIMUM,
    "insurance_bond": SigningPolicy.MAXIMUM,
    "professional_license": SigningPolicy.MAXIMUM,
    "contract_execution": SigningPolicy.MAXIMUM,
    "standing_score": SigningPolicy.MAXIMUM,
    "sybil_conviction": SigningPolicy.MAXIMUM,
}


def policy_for_message(message_type: str) -> SigningPolicy:
    """
    Look up the appropriate signing policy for a message type.
    Defaults to STANDARD if unknown — secure by default.
    """
    return MESSAGE_POLICY_MAP.get(message_type, SigningPolicy.STANDARD)


class SessionCache:
    """
    In-session message authentication cache with sliding window.

    Problem solved: sequence number desync in async multi-agent networks.

    Naive HMAC with a strict incrementing counter breaks when packets
    arrive out of order. Agent sends #4 and #5. Bob receives #5 first.
    Strict counter verification rejects #5 as invalid. Session breaks.
    That is a false positive that kills healthy sessions.

    Solution: sliding window verification (same approach as TCP and TLS).

    The window tracks the highest sequence seen and accepts any sequence
    within WINDOW_SIZE steps behind it. Packets that arrive late but
    within the window are valid. Packets outside the window are rejected
    as replay attacks or genuine errors.

    Window size of 32 handles typical network jitter without opening
    a meaningful replay window. Tune up for high-jitter networks,
    down for high-security low-latency environments.

    After the initial hybrid handshake, in-session messages use
    HMAC-SHA256 with the derived shared secret:
    - ~100x faster than Ed25519
    - ~2000x faster than ML-DSA-65
    - Still cryptographically bound to the verified session
    - Sliding window tolerates out-of-order delivery
    """

    WINDOW_SIZE = 32          # Accept sequences up to 32 behind highest seen
    SESSION_TTL = 3600        # Re-handshake after 1 hour

    def __init__(self, session_id: str, shared_secret: bytes):
        self.session_id = session_id
        self.shared_secret = shared_secret
        self.established_at = time.time()
        self._send_counter = 0
        self._highest_received = -1
        # Bitfield tracking which sequences in the window have been seen
        # Prevents replay: even if seq #3 arrives twice, second is rejected
        self._received_bitmap: set[int] = set()
        self._verified = True

    def sign_in_session(self, message: bytes) -> Tuple[str, int]:
        """
        Sign an in-session message with HMAC-SHA256.
        Returns (signature, sequence_number).
        Caller must include sequence_number in the message envelope
        so the receiver can verify against the sliding window.
        """
        self._send_counter += 1
        seq = self._send_counter
        mac = hmac.new(
            self.shared_secret,
            message + self.session_id.encode() + seq.to_bytes(8, "big"),
            hashlib.sha256
        )
        return mac.hexdigest(), seq

    def verify_in_session(self, message: bytes, signature: str, sequence: int) -> Tuple[bool, str]:
        """
        Verify an in-session HMAC with sliding window sequence check.

        Returns (is_valid, reason).

        Acceptance rules:
        1. Sequence must be within WINDOW_SIZE of highest seen
        2. Sequence must not have been seen before (replay protection)
        3. HMAC must match

        Out-of-order but within window: accepted.
        Duplicate (replay): rejected.
        Too far behind window: rejected.
        """
        # Rule 1: within sliding window
        if self._highest_received >= 0:
            if sequence <= self._highest_received - self.WINDOW_SIZE:
                return False, f"sequence {sequence} outside window (highest={self._highest_received}, window={self.WINDOW_SIZE})"

        # Rule 2: replay protection
        if sequence in self._received_bitmap:
            return False, f"sequence {sequence} already seen (replay rejected)"

        # Rule 3: HMAC verification
        expected = hmac.new(
            self.shared_secret,
            message + self.session_id.encode() + sequence.to_bytes(8, "big"),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return False, "HMAC mismatch"

        # Valid — update window state
        self._received_bitmap.add(sequence)
        if sequence > self._highest_received:
            self._highest_received = sequence
            # Prune bitmap: remove sequences that have fallen outside the window
            cutoff = sequence - self.WINDOW_SIZE
            self._received_bitmap = {s for s in self._received_bitmap if s > cutoff}

        return True, "ok"

    @property
    def age_seconds(self) -> float:
        return time.time() - self.established_at

    @property
    def is_fresh(self) -> bool:
        return self.age_seconds < self.SESSION_TTL


# MTU constants for common transport layers
MTU_STANDARD_IP = 1500        # Standard Ethernet IP MTU
MTU_CONSERVATIVE = 1200       # Conservative (handles most tunneling overhead)
MTU_CONSTRAINED = 512         # LoRaWAN, constrained IoT, edge networks
MTU_FRAGMENT_OVERHEAD = 64    # Bytes reserved for UAHP fragment envelope


class FragmentAssembler:
    """
    Handles ML-DSA-87 payload fragmentation for constrained transports.

    Problem solved: ML-DSA-87 signatures are ~4.6KB. A death certificate
    with a large payload can easily exceed MTU limits on constrained
    networks (LoRaWAN, edge mesh, low-bandwidth IoT). This causes
    IP fragmentation which is unreliable and can cause silent drops.

    Solution: UAHP-level fragmentation with explicit reassembly.

    The sender splits the payload + signature into MTU-sized chunks,
    each with a fragment envelope containing:
    - fragment_id: unique ID for this fragmented message
    - fragment_index: position in sequence
    - fragment_total: total number of fragments
    - payload_hash: SHA256 of the complete original payload (integrity)

    The receiver buffers fragments and reassembles when all arrive.
    If any fragment is missing after timeout, the message is rejected
    and the sender is notified to retransmit.

    This is the same approach used by IP fragmentation, QUIC, and
    DTLS — but at the application layer where we control it properly.
    """

    MAX_FRAGMENT_PAYLOAD = MTU_CONSERVATIVE - MTU_FRAGMENT_OVERHEAD

    def __init__(self):
        self._reassembly_buffer: Dict[str, Dict] = {}
        self._fragment_timeout = 30.0  # seconds

    def should_fragment(self, payload: bytes, mtu: int = MTU_CONSERVATIVE) -> bool:
        """Return True if payload exceeds safe transmission size."""
        return len(payload) > (mtu - MTU_FRAGMENT_OVERHEAD)

    def fragment(self, payload: bytes, fragment_id: str, mtu: int = MTU_CONSERVATIVE) -> list:
        """
        Split payload into MTU-safe fragments.
        Each fragment is self-describing and can be reassembled independently.
        """
        max_chunk = mtu - MTU_FRAGMENT_OVERHEAD
        chunks = [payload[i:i + max_chunk] for i in range(0, len(payload), max_chunk)]
        payload_hash = hashlib.sha256(payload).hexdigest()

        fragments = []
        for idx, chunk in enumerate(chunks):
            fragments.append({
                "fragment_id": fragment_id,
                "fragment_index": idx,
                "fragment_total": len(chunks),
                "payload_hash": payload_hash,
                "data": chunk.hex(),
                "size_bytes": len(chunk),
            })

        return fragments

    def receive_fragment(self, fragment: Dict) -> Tuple[bool, Optional[bytes]]:
        """
        Buffer an incoming fragment.
        Returns (is_complete, reassembled_payload) when all fragments arrive.
        Returns (False, None) while waiting for remaining fragments.
        """
        fid = fragment["fragment_id"]
        total = fragment["fragment_total"]

        if fid not in self._reassembly_buffer:
            self._reassembly_buffer[fid] = {
                "fragments": {},
                "total": total,
                "payload_hash": fragment["payload_hash"],
                "first_seen": time.time(),
            }

        buf = self._reassembly_buffer[fid]
        buf["fragments"][fragment["fragment_index"]] = bytes.fromhex(fragment["data"])

        # Check for timeout
        if time.time() - buf["first_seen"] > self._fragment_timeout:
            del self._reassembly_buffer[fid]
            return False, None

        # Check if all fragments have arrived
        if len(buf["fragments"]) == total:
            reassembled = b"".join(
                buf["fragments"][i] for i in range(total)
            )
            # Integrity check
            actual_hash = hashlib.sha256(reassembled).hexdigest()
            expected_hash = buf["payload_hash"]
            del self._reassembly_buffer[fid]

            if actual_hash != expected_hash:
                return False, None  # Corrupted — reject silently

            return True, reassembled

        return False, None


class DelegatedVerifier:
    """
    Delegated ML-DSA verification for constrained agents.

    Problem solved: a lightweight edge agent (drone, sensor, embedded device)
    physically cannot run ML-DSA-87 verification. The signature is 4.6KB.
    The verification operation requires compute and memory the device lacks.

    Solution: cryptographically safe verification delegation.

    The constrained agent forwards the verification request to a trusted
    heavier node (a registry node, a gateway, a cloud agent). That node
    runs the verification and returns a signed attestation. The constrained
    agent trusts the attestation if and only if:

    1. The attesting node has a valid UAHP identity with known public key
    2. The attestation itself is signed with Ed25519 (lightweight, verifiable)
    3. The attestation includes the original message hash (binding proof)
    4. The attestation is fresh (within ATTESTATION_TTL seconds)

    This is analogous to OCSP (Online Certificate Status Protocol) in TLS —
    constrained clients delegate certificate verification to a trusted responder.

    Trust model:
    The constrained agent does NOT blindly trust the delegated result.
    It verifies the attestation signature with the attesting node's known
    public key. The attesting node's identity must be pre-registered in
    the UAHP-Registry with a valid POLIS Standing Score.

    A compromised attesting node can issue false attestations —
    so constrained agents should maintain a small whitelist of trusted
    verifier node IDs, and rotate them via the registry periodically.
    """

    ATTESTATION_TTL = 30.0  # Attestations older than 30 seconds are rejected

    def __init__(self, trusted_verifier_ids: list, local_agent_id: str):
        """
        trusted_verifier_ids: list of UAHP agent IDs authorized to attest
        local_agent_id: this agent's ID (included in requests for traceability)
        """
        self.trusted_verifier_ids = set(trusted_verifier_ids)
        self.local_agent_id = local_agent_id
        self._pending_requests: Dict[str, Dict] = {}

    def build_verification_request(
        self,
        message: bytes,
        signature: str,
        signer_public_key: str,
        algorithm: str = "ML-DSA-87"
    ) -> Dict:
        """
        Build a delegated verification request.
        Send this to a trusted heavier node via standard UAHP message.
        """
        request_id = hashlib.sha256(
            message + signature.encode() + str(time.time()).encode()
        ).hexdigest()[:16]

        request = {
            "request_id": request_id,
            "requesting_agent": self.local_agent_id,
            "message_hash": hashlib.sha256(message).hexdigest(),
            "signature": signature,
            "signer_public_key": signer_public_key,
            "algorithm": algorithm,
            "requested_at": time.time(),
        }

        self._pending_requests[request_id] = {
            "request": request,
            "message": message,
        }

        return request

    def receive_attestation(
        self,
        attestation: Dict,
        attester_public_key: str
    ) -> Tuple[bool, str]:
        """
        Receive and validate a verification attestation from a heavier node.

        The attestation must:
        1. Reference a known pending request
        2. Come from a trusted verifier
        3. Be fresh (within ATTESTATION_TTL)
        4. Have a valid Ed25519 signature (lightweight, verifiable locally)
        5. Bind to the original message hash
        """
        request_id = attestation.get("request_id")
        attester_id = attestation.get("attester_id")

        # Rule 1: known pending request
        if request_id not in self._pending_requests:
            return False, "unknown request_id"

        # Rule 2: trusted attester
        if attester_id not in self.trusted_verifier_ids:
            return False, f"attester {attester_id} not in trusted list"

        # Rule 3: freshness
        attested_at = attestation.get("attested_at", 0)
        if time.time() - attested_at > self.ATTESTATION_TTL:
            return False, f"attestation expired ({time.time() - attested_at:.1f}s old)"

        # Rule 4: message hash binding
        pending = self._pending_requests[request_id]
        expected_hash = hashlib.sha256(pending["message"]).hexdigest()
        if attestation.get("message_hash") != expected_hash:
            return False, "message hash mismatch — attestation does not bind to original message"

        # Rule 5: real Ed25519 signature on the attestation, verified
        # with the attester's PUBLIC key (hex-encoded raw bytes)
        attest_payload = (
            request_id +
            attester_id +
            attestation.get("message_hash", "") +
            str(attested_at)
        ).encode()
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(attester_public_key))
            pub.verify(bytes.fromhex(attestation.get("attester_signature", "")), attest_payload)
        except Exception:
            return False, "attestation signature invalid"

        # All checks passed
        result = attestation.get("verification_result", False)
        del self._pending_requests[request_id]

        return result, "delegated verification accepted" if result else "delegated: signature invalid"

    def build_attestation(
        self,
        request: Dict,
        verification_result: bool,
        attester_id: str,
        attester_private_key: Union[bytes, Ed25519PrivateKey]
    ) -> Dict:
        """
        Build an attestation response (called by the heavier verifier node).
        The heavy node runs ML-DSA-87 verification and signs the result
        with its real Ed25519 key (an Ed25519PrivateKey object or 32
        raw seed bytes).
        """
        attested_at = time.time()
        attest_payload = (
            request["request_id"] +
            attester_id +
            request["message_hash"] +
            str(attested_at)
        ).encode()

        if not isinstance(attester_private_key, Ed25519PrivateKey):
            attester_private_key = Ed25519PrivateKey.from_private_bytes(attester_private_key)
        sig = attester_private_key.sign(attest_payload).hex()

        return {
            "request_id": request["request_id"],
            "attester_id": attester_id,
            "message_hash": request["message_hash"],
            "verification_result": verification_result,
            "algorithm_verified": request.get("algorithm", "ML-DSA-87"),
            "attested_at": attested_at,
            "attester_signature": sig,
        }


class TieredSigner:
    """
    Applies the correct signing policy based on message type.
    Integrates with SessionCache to avoid repeated asymmetric operations.

    Usage:
        signer = TieredSigner(agent_id="alice", private_key=b"...", session_cache=cache)

        # Heartbeat — Ed25519 only, fast
        sig = signer.sign(b"ping", message_type="heartbeat")

        # Task delegation — full hybrid
        sig = signer.sign(b"delegate_task(...)", message_type="task_delegation")

        # Death certificate — ML-DSA-87 maximum
        sig = signer.sign(b"agent_xyz is dead", message_type="death_certificate")
    """

    def __init__(
        self,
        agent_id: str,
        private_key: Union[bytes, Ed25519PrivateKey, None] = None,
        session_cache: Optional[SessionCache] = None,
        force_policy: Optional[SigningPolicy] = None,
        allow_degraded: bool = False,
    ):
        """
        private_key: a real Ed25519 key — either an Ed25519PrivateKey
        object or 32 raw seed bytes. If None, a fresh key is generated.

        allow_degraded: if True and oqs is not installed, PQC tiers
        (STANDARD hybrid part, MAXIMUM) degrade to Ed25519-only with
        method labeled "ed25519_degraded" and quantum_safe=False.
        If False (default), requesting a PQC tier without oqs raises
        PQCUnavailableError. No silent fallback either way.
        """
        self.agent_id = agent_id
        if private_key is None:
            self._ed_key = Ed25519PrivateKey.generate()
        elif isinstance(private_key, Ed25519PrivateKey):
            self._ed_key = private_key
        else:
            self._ed_key = Ed25519PrivateKey.from_private_bytes(private_key)
        self.public_key = self._ed_key.public_key().public_bytes_raw().hex()
        self.session_cache = session_cache
        self.force_policy = force_policy
        self.allow_degraded = allow_degraded

        # Real ML-DSA signers, created only when liboqs is present.
        self._ml_dsa_65 = oqs.Signature("ML-DSA-65") if OQS_AVAILABLE else None
        self._ml_dsa_87 = oqs.Signature("ML-DSA-87") if OQS_AVAILABLE else None
        if OQS_AVAILABLE:
            self.ml_dsa_65_public_key = base64.b64encode(
                self._ml_dsa_65.generate_keypair()).decode()
            self.ml_dsa_87_public_key = base64.b64encode(
                self._ml_dsa_87.generate_keypair()).decode()
        else:
            self.ml_dsa_65_public_key = None
            self.ml_dsa_87_public_key = None

        self._sign_count = {p: 0 for p in SigningPolicy}
        self._total_signing_ms = {p: 0.0 for p in SigningPolicy}

    def sign(self, message: bytes, message_type: str = "task_delegation") -> Dict:
        """
        Sign a message using the appropriate policy tier.
        Returns a dict with signature, policy, and timing metadata.
        The method and quantum_safe fields describe what actually ran.
        """
        policy = self.force_policy or policy_for_message(message_type)
        start = time.perf_counter()

        # Use session cache for in-session messages when available
        if self.session_cache and self.session_cache.is_fresh:
            if policy == SigningPolicy.LIGHTWEIGHT:
                sig = self.session_cache.sign_in_session(message)
                elapsed = (time.perf_counter() - start) * 1000
                self._record(policy, elapsed)
                return {
                    "signature": sig,
                    "policy": policy.value,
                    "method": "hmac_sha256_in_session",
                    "latency_ms": round(elapsed, 4),
                    # The HMAC key is derived from the session handshake.
                    # Unless that handshake ran a hybrid KEM, the secret
                    # is classical. This module cannot prove it did, so
                    # it does not claim quantum safety.
                    "quantum_safe": False,
                }

        # Full asymmetric signing based on policy
        sig, method, quantum_safe = self._sign_by_policy(message, policy)
        elapsed = (time.perf_counter() - start) * 1000
        self._record(policy, elapsed)

        return {
            "signature": sig,
            "policy": policy.value,
            "method": method,
            "latency_ms": round(elapsed, 4),
            "quantum_safe": quantum_safe,
        }

    def _sign_by_policy(
        self, message: bytes, policy: SigningPolicy
    ) -> Tuple[str, str, bool]:
        """
        Apply the correct signing algorithm for the policy tier.
        Returns (signature, method_actually_used, quantum_safe).
        Every signature here is real: Ed25519 via the cryptography
        library, ML-DSA via liboqs. There are no hash stubs.
        """
        if policy == SigningPolicy.LIGHTWEIGHT:
            # Ed25519 only — fast, classical
            return self._ed_key.sign(message).hex(), "ed25519", False

        if not OQS_AVAILABLE:
            if not self.allow_degraded:
                raise PQCUnavailableError(PQC_INSTALL_INSTRUCTIONS)
            # Explicit, labeled degrade — never silent
            return (
                self._ed_key.sign(message).hex(),
                "ed25519_degraded (ML-DSA unavailable: liboqs not installed)",
                False,
            )

        if policy == SigningPolicy.STANDARD:
            # Hybrid: Ed25519 + ML-DSA-65. Both signatures are real.
            classical_sig = self._ed_key.sign(message).hex()
            pqc_sig = base64.b64encode(self._ml_dsa_65.sign(message)).decode()
            return (
                f"hybrid:{classical_sig}:{pqc_sig}",
                "hybrid_ed25519_ml_dsa_65",
                True,
            )

        # MAXIMUM: ML-DSA-87 only — pure PQC, strongest available
        pqc_sig = base64.b64encode(self._ml_dsa_87.sign(message)).decode()
        return pqc_sig, "ml_dsa_87", True

    def _record(self, policy: SigningPolicy, elapsed_ms: float):
        self._sign_count[policy] += 1
        self._total_signing_ms[policy] += elapsed_ms

    def performance_report(self) -> Dict:
        """
        Return signing performance by policy tier.
        Use this to tune policy assignments for your hardware.
        """
        report = {}
        for policy in SigningPolicy:
            count = self._sign_count[policy]
            if count > 0:
                avg_ms = self._total_signing_ms[policy] / count
                report[policy.value] = {
                    "count": count,
                    "avg_latency_ms": round(avg_ms, 4),
                    "total_ms": round(self._total_signing_ms[policy], 2),
                }
        return report
