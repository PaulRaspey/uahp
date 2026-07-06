"""
UAHP Core v1.1 — Identity, Handshake, Liveness, Death Certificates, Receipts.

The trust primitives that everything else in the stack depends on.

Cryptography (v1.1, honest accounting):
  - Identity:   Ed25519 keypairs (asymmetric). The public key is a real
                public key, not a hash. Anyone can verify; only the
                holder of the private key can sign.
  - Handshake:  Message-based mutual challenge-response. Each party
                verifies the OTHER party's Ed25519 signature over the
                handshake transcript. Session secrecy comes from an
                ephemeral X25519 exchange bound to that transcript.
  - Receipts:   Ed25519-signed, chain-hashed, sequence-numbered.
  - Death:      A death certificate is signed by the dying agent's key,
                then the private key reference is destroyed and the agent_id
                enters a revocation list. Signatures timestamped after
                death are rejected by verifiers.
  - Replay:     Nonce cache with a sliding window, monotonic sequence
                numbers on receipts, and a clock-skew tolerance of
                +/-120 seconds on all timestamp checks.

Post-quantum status: this module is classical (Ed25519/X25519). Hybrid
ML-KEM-768/ML-DSA-65 support is a tested-feature-flag roadmap item, not
a shipped property. No quantum-resistance claim is made here.

Author: Paul Raspey
License: MIT
"""

import hashlib
import json
import secrets
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ── ANSI ─────────────────────────────────────────────────────────────────────

GREEN = "\033[92m"
TEAL = "\033[96m"
AMBER = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Protocol constants ───────────────────────────────────────────────────────

PROTOCOL_VERSION = "1.1.0"
CLOCK_SKEW_TOLERANCE = 120.0   # seconds, applied to all timestamp checks
NONCE_WINDOW = 300.0           # seconds a nonce stays in the replay cache
HKDF_INFO_SESSION = b"UAHP_SESSION_v1.1"


class HandshakeError(Exception):
    """Raised when a handshake message fails validation."""


class IdentityRevoked(Exception):
    """Raised when a revoked (dead) identity attempts to sign."""


# ── Signature verification (public-key, works for any verifier) ─────────────

def verify_signature(public_key_hex: str, payload: str, signature_hex: str) -> bool:
    """
    Verify an Ed25519 signature using only the signer's PUBLIC key.
    Any third party can run this check; possession of the private key
    is never required (unlike HMAC, where every verifier could forge).
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), payload.encode())
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _canonical(obj: Dict) -> str:
    """Deterministic JSON serialization for signing/transcripts."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# ── Identity ─────────────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    """
    A UAHP agent identity backed by an Ed25519 keypair.

    public_key is the hex-encoded raw Ed25519 public key (32 bytes /
    64 hex chars) — safe to publish. The private key lives only in
    memory on this object and is destroyed on revocation.
    """
    agent_id: str
    public_key: str
    created_at: float
    protocol_version: str = PROTOCOL_VERSION
    metadata: Dict = field(default_factory=dict)
    revoked: bool = False
    _private_key: Optional[Ed25519PrivateKey] = field(
        default=None, repr=False, compare=False
    )

    @classmethod
    def create(cls, metadata: Optional[Dict] = None) -> "AgentIdentity":
        """
        Create a new identity. agent_id is self-certifying:
        agent_id = sha256(raw public key bytes), hex encoded.
        Human-friendly labels belong in metadata["display_name"].
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw().hex()
        return cls(
            agent_id=hashlib.sha256(bytes.fromhex(public_key)).hexdigest(),
            public_key=public_key,
            created_at=time.time(),
            metadata=metadata or {},
            _private_key=private_key,
        )

    def sign(self, payload: str) -> str:
        """Ed25519 signature over payload. Raises if this identity is revoked."""
        if self.revoked or self._private_key is None:
            raise IdentityRevoked(
                f"Identity {self.agent_id[:8]} is revoked; its private key is destroyed."
            )
        return self._private_key.sign(payload.encode()).hex()

    def verify(self, payload: str, signature: str) -> bool:
        """Verify a signature against this identity's PUBLIC key only."""
        return verify_signature(self.public_key, payload, signature)

    def revoke(self) -> None:
        """
        Destroy the private key reference and mark the identity revoked.
        Note: Python cannot guarantee memory zeroization; we drop the only
        reference to the key object and rely on the revocation list for
        protocol-level enforcement.
        """
        self._private_key = None
        self.revoked = True

    def to_public(self) -> Dict:
        """Export only public fields (safe to transmit)."""
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key,
            "created_at": self.created_at,
            "protocol_version": self.protocol_version,
            "metadata": self.metadata,
        }


# ── Handshake ────────────────────────────────────────────────────────────────

@dataclass
class HandshakeResult:
    """Result of a mutual authentication handshake."""
    success: bool
    session_token: str = ""
    shared_secret: bytes = b""
    error: str = ""


@dataclass
class Session:
    """An active authenticated session between two agents."""
    session_token: str
    agent_a_id: str
    agent_b_id: str
    shared_secret: bytes
    created_at: float
    last_activity: float
    message_count: int = 0

    def is_expired(self, timeout_seconds: float = 3600) -> bool:
        return (time.time() - self.last_activity) > timeout_seconds

    def touch(self):
        self.last_activity = time.time()
        self.message_count += 1


# ── Receipts ─────────────────────────────────────────────────────────────────

@dataclass
class Receipt:
    """
    Signed, tamper-evident proof of work. Chain-hashed (each receipt
    includes the hash of the previous receipt) and sequence-numbered
    (monotonic per agent) for replay and reordering detection.
    """
    receipt_id: str
    agent_id: str
    task_id: str
    action: str
    success: bool
    timestamp: float
    sequence: int
    input_hash: str
    output_hash: str
    previous_hash: str  # chain link
    signature: str
    duration_ms: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)

    def signed_payload(self) -> str:
        return (
            f"{self.agent_id}:{self.task_id}:{self.action}:{self.success}:"
            f"{self.timestamp}:{self.sequence}:{self.duration_ms}:"
            f"{self.input_hash}:{self.output_hash}:{self.previous_hash}"
        )


# ── Death Certificates ───────────────────────────────────────────────────────

@dataclass
class DeathCertificate:
    """
    Irreversible declaration that an agent is no longer operational.
    Signed by the dying agent's own key as its final act, after which
    the private key is destroyed and the agent_id is revoked. Any signature
    timestamped after this certificate is rejected by verifiers.
    """
    cert_id: str
    agent_id: str
    timestamp: float
    reason: str
    final_receipt_hash: str
    signature: str
    public_key: str = ""  # dead agent's public key, for independent verification
    declared_by: str = "self"  # who declared the death (audit trail)

    def to_dict(self) -> Dict:
        return asdict(self)

    def signed_payload(self) -> str:
        return (
            f"death:{self.cert_id}:{self.agent_id}:{self.reason}:"
            f"{self.declared_by}:{self.final_receipt_hash}:{self.timestamp}"
        )


# ── Core Engine ──────────────────────────────────────────────────────────────

class UAHPCore:
    """
    Core trust primitives for the UAHP stack.

    Manages the lifecycle of agent identities:
        create -> handshake -> produce receipts -> liveness checks -> death

    The handshake is message-based and works across processes: each side
    runs its own UAHPCore and only ever sees the peer's public fields.

        # Process A                          # Process B
        m1 = core_a.handshake_init(alice, bob_public)
                        --- m1 over the wire --->
                                             m2 = core_b.handshake_respond(bob, m1)
                        <--- m2 over the wire ---
        m3 = core_a.handshake_finalize(alice, m2)
                        --- m3 over the wire --->
                                             res = core_b.handshake_complete(bob, m3)

    Both sides now hold the same session token and a real shared secret
    derived from an ephemeral X25519 exchange bound to the transcript.
    """

    def __init__(self):
        self._identities: Dict[str, AgentIdentity] = {}
        self._receipts: Dict[str, List[Receipt]] = {}
        self._receipt_chains: Dict[str, str] = {}  # agent_id -> last receipt hash
        self._receipt_sequences: Dict[str, int] = {}  # agent_id -> last sequence number
        self._sessions: Dict[str, Session] = {}
        self._dead_agents: Dict[str, DeathCertificate] = {}
        self._revoked: set = set()  # revocation list (agent_ids)
        self._nonce_cache: Dict[str, float] = {}  # nonce -> expiry
        self._pending_handshakes: Dict[str, Dict] = {}  # nonce -> state

    # ── Replay protection helpers ────────────────────────────────────────

    def _check_timestamp(self, ts: float, context: str) -> None:
        if abs(time.time() - ts) > CLOCK_SKEW_TOLERANCE:
            raise HandshakeError(
                f"{context}: timestamp outside +/-{CLOCK_SKEW_TOLERANCE:.0f}s skew tolerance"
            )

    def _check_and_store_nonce(self, nonce: str, context: str) -> None:
        now = time.time()
        # Prune expired nonces (sliding window)
        expired = [n for n, exp in self._nonce_cache.items() if exp < now]
        for n in expired:
            del self._nonce_cache[n]
        if nonce in self._nonce_cache:
            raise HandshakeError(f"{context}: nonce replay detected")
        self._nonce_cache[nonce] = now + NONCE_WINDOW

    # ── Identity ─────────────────────────────────────────────────────────

    def create_identity(self, metadata: Optional[Dict] = None) -> AgentIdentity:
        """Create and register a new agent identity."""
        identity = AgentIdentity.create(metadata)
        self._identities[identity.agent_id] = identity
        self._receipts[identity.agent_id] = []
        self._receipt_chains[identity.agent_id] = "genesis"
        self._receipt_sequences[identity.agent_id] = 0
        return identity

    def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        return self._identities.get(agent_id)

    def is_alive(self, agent_id: str) -> bool:
        """Liveness check: identity exists and is not revoked."""
        return (
            agent_id in self._identities
            and agent_id not in self._dead_agents
            and agent_id not in self._revoked
        )

    def is_revoked(self, agent_id: str) -> bool:
        return agent_id in self._revoked or agent_id in self._dead_agents

    # ── Handshake (message-based, mutual, cross-process) ─────────────────

    def handshake_init(self, initiator: AgentIdentity, responder_public: Dict) -> Dict:
        """
        Step 1 (runs on A): produce the opening handshake message.
        Contains A's public identity, a fresh nonce, and an ephemeral
        X25519 public key. Signed by A.
        """
        if self.is_revoked(initiator.agent_id):
            raise HandshakeError(f"Initiator {initiator.agent_id[:8]} is dead/revoked")
        if self.is_revoked(responder_public.get("agent_id", "")):
            raise HandshakeError(
                f"Responder {responder_public.get('agent_id', '?')[:8]} is dead/revoked"
            )

        eph_private = x25519.X25519PrivateKey.generate()
        nonce_a = secrets.token_hex(16)
        body = {
            "type": "uahp.handshake.1",
            "protocol_version": PROTOCOL_VERSION,
            "from": initiator.to_public(),
            "to_agent_id": responder_public["agent_id"],
            "nonce": nonce_a,
            "eph_pub": eph_private.public_key().public_bytes_raw().hex(),
            "timestamp": time.time(),
        }
        message = dict(body)
        message["signature"] = initiator.sign(_canonical(body))
        self._pending_handshakes[nonce_a] = {
            "role": "initiator",
            "eph_private": eph_private,
            "m1_body": body,
            "responder_public": responder_public,
        }
        return message

    def handshake_respond(self, responder: AgentIdentity, m1: Dict) -> Dict:
        """
        Step 2 (runs on B): validate A's opening message, then answer
        with B's own nonce, ephemeral key, and a signature over the
        transcript so far. B derives the shared secret here.
        """
        if self.is_revoked(responder.agent_id):
            raise HandshakeError(f"Responder {responder.agent_id[:8]} is dead/revoked")

        body = {k: v for k, v in m1.items() if k != "signature"}
        peer = m1.get("from", {})
        peer_agent_id = peer.get("agent_id", "")

        self._check_timestamp(m1.get("timestamp", 0), "handshake.1")
        self._check_and_store_nonce(m1.get("nonce", ""), "handshake.1")
        if self.is_revoked(peer_agent_id):
            raise HandshakeError(f"Initiator {peer_agent_id[:8]} is dead/revoked")
        if m1.get("to_agent_id") != responder.agent_id:
            raise HandshakeError("handshake.1 addressed to a different agent")
        if not verify_signature(peer.get("public_key", ""), _canonical(body), m1.get("signature", "")):
            raise HandshakeError("handshake.1: initiator signature verification FAILED")

        eph_private = x25519.X25519PrivateKey.generate()
        nonce_b = secrets.token_hex(16)
        m2_body = {
            "type": "uahp.handshake.2",
            "protocol_version": PROTOCOL_VERSION,
            "from": responder.to_public(),
            "to_agent_id": peer_agent_id,
            "nonce": nonce_b,
            "in_reply_to": m1["nonce"],
            "eph_pub": eph_private.public_key().public_bytes_raw().hex(),
            "timestamp": time.time(),
        }
        # Transcript binds both messages: signature covers what B saw.
        transcript = hashlib.sha256(
            (_canonical(body) + _canonical(m2_body)).encode()
        ).hexdigest()
        message = dict(m2_body)
        message["transcript"] = transcript
        message["signature"] = responder.sign(f"uahp-hs2:{transcript}")

        # B derives the shared secret from the ephemeral exchange.
        peer_eph = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(m1["eph_pub"]))
        raw_shared = eph_private.exchange(peer_eph)
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(transcript),
            info=HKDF_INFO_SESSION,
        ).derive(raw_shared)

        self._pending_handshakes[nonce_b] = {
            "role": "responder",
            "transcript": transcript,
            "shared_secret": shared_secret,
            "peer_public": peer,
            "self_agent_id": responder.agent_id,
        }
        return message

    def handshake_finalize(self, initiator: AgentIdentity, m2: Dict) -> Dict:
        """
        Step 3 (runs on A): verify B's signature over the transcript with
        B's PUBLIC key, derive the same shared secret, establish the
        session, and return the confirmation message for B.
        """
        state = self._pending_handshakes.pop(m2.get("in_reply_to", ""), None)
        if state is None or state.get("role") != "initiator":
            raise HandshakeError("handshake.2: no matching pending handshake")

        peer = m2.get("from", {})
        peer_agent_id = peer.get("agent_id", "")
        self._check_timestamp(m2.get("timestamp", 0), "handshake.2")
        self._check_and_store_nonce(m2.get("nonce", ""), "handshake.2")
        if self.is_revoked(peer_agent_id):
            raise HandshakeError(f"Responder {peer_agent_id[:8]} is dead/revoked")

        # Recompute the transcript independently — never trust the wire copy.
        m2_body = {
            k: v for k, v in m2.items() if k not in ("signature", "transcript")
        }
        transcript = hashlib.sha256(
            (_canonical(state["m1_body"]) + _canonical(m2_body)).encode()
        ).hexdigest()
        if transcript != m2.get("transcript"):
            raise HandshakeError("handshake.2: transcript mismatch")

        # Verify the RESPONDER's signature with the responder's public key.
        expected_pub = state["responder_public"].get("public_key", peer.get("public_key", ""))
        if not verify_signature(expected_pub, f"uahp-hs2:{transcript}", m2.get("signature", "")):
            raise HandshakeError("handshake.2: responder signature verification FAILED")

        # Derive the same shared secret from the ephemeral exchange.
        peer_eph = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(m2["eph_pub"]))
        raw_shared = state["eph_private"].exchange(peer_eph)
        shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(transcript),
            info=HKDF_INFO_SESSION,
        ).derive(raw_shared)

        session_token = transcript[:32]
        now = time.time()
        self._sessions[session_token] = Session(
            session_token=session_token,
            agent_a_id=initiator.agent_id,
            agent_b_id=peer_agent_id,
            shared_secret=shared_secret,
            created_at=now,
            last_activity=now,
        )

        return {
            "type": "uahp.handshake.3",
            "from_agent_id": initiator.agent_id,
            "in_reply_to": m2["nonce"],
            "timestamp": now,
            "signature": initiator.sign(f"uahp-hs3:{transcript}"),
        }

    def handshake_complete(self, responder: AgentIdentity, m3: Dict) -> HandshakeResult:
        """
        Step 4 (runs on B): verify A's confirmation signature with A's
        PUBLIC key and activate the session. Mutual authentication is
        now complete — each side has verified the other.
        """
        state = self._pending_handshakes.pop(m3.get("in_reply_to", ""), None)
        if state is None or state.get("role") != "responder":
            return HandshakeResult(False, error="handshake.3: no matching pending handshake")

        try:
            self._check_timestamp(m3.get("timestamp", 0), "handshake.3")
        except HandshakeError as e:
            return HandshakeResult(False, error=str(e))

        transcript = state["transcript"]
        peer = state["peer_public"]
        if self.is_revoked(peer.get("agent_id", "")):
            return HandshakeResult(False, error=f"Initiator {peer.get('agent_id','?')[:8]} is dead/revoked")
        if not verify_signature(peer.get("public_key", ""), f"uahp-hs3:{transcript}", m3.get("signature", "")):
            return HandshakeResult(False, error="handshake.3: initiator signature verification FAILED")

        session_token = transcript[:32]
        now = time.time()
        self._sessions[session_token] = Session(
            session_token=session_token,
            agent_a_id=peer.get("agent_id", ""),
            agent_b_id=state["self_agent_id"],
            shared_secret=state["shared_secret"],
            created_at=now,
            last_activity=now,
        )
        return HandshakeResult(
            success=True,
            session_token=session_token,
            shared_secret=state["shared_secret"],
        )

    def handshake(self, id_a: AgentIdentity, id_b: AgentIdentity) -> HandshakeResult:
        """
        Convenience wrapper: run the full 3-message mutual handshake
        in-process. For cross-process use, call handshake_init /
        handshake_respond / handshake_finalize / handshake_complete
        and move the messages over your transport.
        """
        try:
            m1 = self.handshake_init(id_a, id_b.to_public())
            m2 = self.handshake_respond(id_b, m1)
            m3 = self.handshake_finalize(id_a, m2)
            return self.handshake_complete(id_b, m3)
        except (HandshakeError, IdentityRevoked) as e:
            return HandshakeResult(False, error=str(e))

    def get_session(self, token: str) -> Optional[Session]:
        session = self._sessions.get(token)
        if session and not session.is_expired():
            return session
        return None

    # ── Receipts ─────────────────────────────────────────────────────────

    def create_receipt(
        self,
        identity: AgentIdentity,
        task_id: str,
        action: str,
        success: bool,
        input_data: str,
        output_data: str,
        duration_ms: float = 0.0,
    ) -> Receipt:
        """
        Create a signed, chain-hashed, sequence-numbered receipt.

        Each receipt links to the previous one via previous_hash and
        carries a monotonic sequence number, so both tampering and
        replay/reordering are detectable.
        """
        if self.is_revoked(identity.agent_id):
            raise IdentityRevoked(
                f"Dead agent {identity.agent_id[:8]} cannot create receipts"
            )

        input_hash = hashlib.sha256(input_data.encode()).hexdigest()
        output_hash = hashlib.sha256(output_data.encode()).hexdigest()
        previous_hash = self._receipt_chains.get(identity.agent_id, "genesis")
        sequence = self._receipt_sequences.get(identity.agent_id, 0) + 1

        receipt = Receipt(
            receipt_id=str(uuid.uuid4()),
            agent_id=identity.agent_id,
            task_id=task_id,
            action=action,
            success=success,
            timestamp=time.time(),
            sequence=sequence,
            input_hash=input_hash,
            output_hash=output_hash,
            previous_hash=previous_hash,
            signature="",
            duration_ms=duration_ms,
        )
        receipt.signature = identity.sign(receipt.signed_payload())

        self._receipts[identity.agent_id].append(receipt)
        self._receipt_chains[identity.agent_id] = hashlib.sha256(
            receipt.signature.encode()
        ).hexdigest()
        self._receipt_sequences[identity.agent_id] = sequence

        return receipt

    def get_receipts(
        self, agent_id: str, limit: Optional[int] = None
    ) -> List[Receipt]:
        """Return an agent's receipts. With limit, return only the last N."""
        receipts = self._receipts.get(agent_id, [])
        if limit:
            return receipts[-limit:]
        return receipts

    def verify_receipt(self, receipt: Receipt, public_key: str) -> bool:
        """
        Verify a single receipt with the agent's PUBLIC key. Rejects
        signatures timestamped after the agent's death certificate.
        """
        cert = self._dead_agents.get(receipt.agent_id)
        if cert and receipt.timestamp > cert.timestamp + CLOCK_SKEW_TOLERANCE:
            return False  # signed "after death" — key compromise or forgery
        return verify_signature(public_key, receipt.signed_payload(), receipt.signature)

    def verify_receipt_chain(self, agent_id: str) -> bool:
        """Verify the entire receipt chain: signatures, links, sequence order."""
        receipts = self.get_receipts(agent_id)
        if not receipts:
            return True

        identity = self._identities.get(agent_id)
        if not identity:
            return False

        expected_prev = "genesis"
        expected_seq = 1
        for r in receipts:
            if r.previous_hash != expected_prev:
                return False
            if r.sequence != expected_seq:
                return False  # replayed, dropped, or reordered receipt
            if not verify_signature(identity.public_key, r.signed_payload(), r.signature):
                return False
            expected_prev = hashlib.sha256(r.signature.encode()).hexdigest()
            expected_seq += 1

        return True

    # ── Death Certificates ───────────────────────────────────────────────

    def declare_death(
        self, agent_id: str, reason: str = "silent", declared_by: str = "self"
    ) -> Optional[DeathCertificate]:
        """
        Issue an irreversible death certificate.

        The certificate is the agent's final signature. Immediately after
        signing, the private key reference is destroyed and the agent_id is
        added to the revocation list: the agent can never handshake or
        produce receipts again, and post-death signatures are rejected.
        """
        if agent_id not in self._identities:
            return None
        if agent_id in self._dead_agents:
            return self._dead_agents[agent_id]

        identity = self._identities[agent_id]
        final_hash = self._receipt_chains.get(agent_id, "genesis")

        cert = DeathCertificate(
            cert_id=str(uuid.uuid4()),
            agent_id=agent_id,
            timestamp=time.time(),
            reason=reason,
            final_receipt_hash=final_hash,
            signature="",
            public_key=identity.public_key,
            declared_by=declared_by,
        )
        cert.signature = identity.sign(cert.signed_payload())

        # The point of no return: destroy the key, revoke the agent_id.
        identity.revoke()
        self._dead_agents[agent_id] = cert
        self._revoked.add(agent_id)
        return cert

    def get_death_certificate(self, agent_id: str) -> Optional[DeathCertificate]:
        return self._dead_agents.get(agent_id)

    def record_death_certificate(self, cert: DeathCertificate) -> bool:
        """
        Honor a PEER's death certificate. The certificate is verified
        against its embedded public key before being recorded; once
        recorded, this core refuses handshakes with the dead agent_id and
        rejects any of its signatures timestamped after the certificate.
        """
        if not self.verify_death_certificate(cert):
            return False
        self._dead_agents[cert.agent_id] = cert
        self._revoked.add(cert.agent_id)
        return True

    @staticmethod
    def verify_death_certificate(cert: DeathCertificate) -> bool:
        """Anyone can verify a death certificate with the embedded public key."""
        return verify_signature(cert.public_key, cert.signed_payload(), cert.signature)

    # ── Trust Inputs (for ReputationEngine) ──────────────────────────────

    def get_trust_inputs(self, agent_id: str) -> Dict:
        """
        Compute raw trust inputs from receipts for ReputationEngine.
        """
        receipts = self.get_receipts(agent_id)
        if not receipts:
            return {
                "delivery_rate": 0.0,
                "total_tasks": 0,
                "success_count": 0,
                "failure_count": 0,
                "latest_timestamp": 0.0,
                "oldest_timestamp": 0.0,
                "chain_valid": True,
                "is_alive": self.is_alive(agent_id),
            }

        successes = sum(1 for r in receipts if r.success)
        timestamps = [r.timestamp for r in receipts]

        return {
            "delivery_rate": successes / len(receipts),
            "total_tasks": len(receipts),
            "success_count": successes,
            "failure_count": len(receipts) - successes,
            "latest_timestamp": max(timestamps),
            "oldest_timestamp": min(timestamps),
            "chain_valid": self.verify_receipt_chain(agent_id),
            "is_alive": self.is_alive(agent_id),
        }


# ── Demo ─────────────────────────────────────────────────────────────────────

def demo():
    print(f"\n{BOLD}{'='*60}")
    print(f"  UAHP Core v1.1 Demo — real Ed25519, mutual verification")
    print(f"  Identity + Handshake + Receipts + Death Certificates")
    print(f"{'='*60}{RESET}\n")

    core = UAHPCore()

    # Create identities (real Ed25519 keypairs)
    alice = core.create_identity({"name": "Alice", "role": "analyst"})
    bob = core.create_identity({"name": "Bob", "role": "reviewer"})
    print(f"{GREEN}[1] Alice: {alice.agent_id[:12]}...  pubkey {alice.public_key[:16]}...{RESET}")
    print(f"{GREEN}[1] Bob:   {bob.agent_id[:12]}...  pubkey {bob.public_key[:16]}...{RESET}")

    # Mutual message-based handshake
    m1 = core.handshake_init(alice, bob.to_public())
    m2 = core.handshake_respond(bob, m1)      # Bob VERIFIES Alice's signature
    m3 = core.handshake_finalize(alice, m2)   # Alice VERIFIES Bob's signature
    result = core.handshake_complete(bob, m3) # Bob VERIFIES Alice's confirmation
    print(f"\n{TEAL}[2] Mutual handshake: {'SUCCESS' if result.success else 'FAILED'}{RESET}")
    print(f"    Session: {result.session_token[:16]}...  "
          f"shared secret (X25519+HKDF): {result.shared_secret.hex()[:16]}...")

    # Replay attempt: resend m1
    try:
        core.handshake_respond(bob, m1)
        print(f"    {RED}Replay NOT detected (bug){RESET}")
    except HandshakeError as e:
        print(f"    Replayed handshake rejected: {e}")

    # Create receipts (chain-hashed + sequence numbers)
    print(f"\n{AMBER}[3] Receipt chain for Alice:{RESET}")
    for i in range(5):
        success = i != 3  # one failure
        r = core.create_receipt(
            alice, f"task-{i:03d}", "analyze",
            success, f"input-{i}", f"output-{i}",
        )
        status = f"{GREEN}OK{RESET}" if success else f"{RED}FAIL{RESET}"
        print(f"    Receipt seq={r.sequence} {r.receipt_id[:8]}... {status} "
              f"chain: ...{r.previous_hash[-8:]}")

    chain_ok = core.verify_receipt_chain(alice.agent_id)
    print(f"\n{GREEN}[4] Receipt chain integrity: {'VALID' if chain_ok else 'TAMPERED'}{RESET}")

    inputs = core.get_trust_inputs(alice.agent_id)
    print(f"\n{TEAL}[5] Trust inputs for Alice:{RESET}")
    print(f"    Delivery rate: {inputs['delivery_rate']:.0%}")
    print(f"    Total tasks:   {inputs['total_tasks']}")
    print(f"    Chain valid:   {inputs['chain_valid']}")
    print(f"    Alive:         {inputs['is_alive']}")

    print(f"\n{AMBER}[6] Liveness:{RESET}")
    print(f"    Alice: {core.is_alive(alice.agent_id)}")
    print(f"    Bob:   {core.is_alive(bob.agent_id)}")

    # Death certificate: signed, then key destroyed, then revoked
    cert = core.declare_death(bob.agent_id, "backend_timeout")
    print(f"\n{RED}[7] Death certificate for Bob:{RESET}")
    print(f"    Cert ID:  {cert.cert_id[:12]}...")
    print(f"    Reason:   {cert.reason}")
    print(f"    Cert verifies: {UAHPCore.verify_death_certificate(cert)}")
    print(f"    Bob alive: {core.is_alive(bob.agent_id)}")

    # Dead agent can't handshake
    result2 = core.handshake(alice, bob)
    print(f"\n{DIM}[8] Handshake with dead Bob: {'SUCCESS' if result2.success else 'REJECTED'}")
    print(f"    Error: {result2.error}{RESET}")

    # Dead agent can't sign — the key no longer exists
    try:
        core.create_receipt(bob, "task-999", "review", True, "x", "y")
        print(f"    Dead receipt: SHOULD NOT HAPPEN")
    except IdentityRevoked as e:
        print(f"    Dead receipt blocked: {e}")

    print(f"\n{BOLD}UAHP Core v1.1 validated{RESET}\n")


if __name__ == "__main__":
    demo()
