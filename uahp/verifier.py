"""
UAHP compliance verifier.

Runs a live candidate agent (speaking the UAHP HTTP surface) against
the protocol requirements and reports PASS or FAIL per requirement:

    1. identity          real Ed25519 identity, verifiable signatures
    2. handshake         3-message mutual handshake completes, shared
                         secret digests match
    3. receipts          signed receipts verify both directions, and
                         tampered receipts are rejected
    4. replay            replayed handshake openings are refused
    5. revocation        death certificate honored: post-death signing
                         is refused (DESTRUCTIVE: kills the candidate)
    6. crypto_mode       declared crypto mode matches what actually ran

The revocation check is destructive by design: it asks the candidate
to issue its own death certificate. Run it against a disposable agent.
"""

import hashlib
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .core import UAHPCore, HandshakeError, Receipt, DeathCertificate, verify_signature


@dataclass
class CheckResult:
    requirement: str
    passed: bool
    detail: str


def _http_json(method: str, url: str, payload=None, timeout=5.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode())


def _post(url: str, payload) -> tuple:
    """POST that returns (status, body) instead of raising on 4xx."""
    try:
        return _http_json("POST", url, payload)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except (ValueError, TypeError):
            return e.code, {}


class AgentVerifier:
    """Verify a running agent at base_url (e.g. http://127.0.0.1:8100)."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.core = UAHPCore()
        self.me = self.core.create_identity({"name": "uahp-verifier"})
        self.peer_public: Optional[dict] = None
        self.results: List[CheckResult] = []

    def _record(self, requirement: str, passed: bool, detail: str) -> bool:
        self.results.append(CheckResult(requirement, passed, detail))
        return passed

    # ── 1. Real Ed25519 identity ─────────────────────────────────────────

    def check_identity(self) -> bool:
        try:
            _, pub = _http_json("GET", f"{self.base}/uahp/public")
        except (urllib.error.URLError, OSError) as e:
            return self._record("identity", False, f"agent unreachable: {e}")
        self.peer_public = pub

        key_hex = pub.get("public_key", "")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex))
        except (ValueError, TypeError):
            return self._record(
                "identity", False,
                "public_key is not a valid 32-byte Ed25519 key")

        p1, p2 = f"uahp-verify:{secrets.token_hex(8)}", f"uahp-verify:{secrets.token_hex(8)}"
        s1_status, s1 = _post(f"{self.base}/uahp/sign", {"payload": p1})
        s2_status, s2 = _post(f"{self.base}/uahp/sign", {"payload": p2})
        if s1_status != 200 or s2_status != 200:
            return self._record("identity", False, "agent refused to sign a challenge")
        sig1, sig2 = s1.get("signature", ""), s2.get("signature", "")
        if not verify_signature(key_hex, p1, sig1):
            return self._record(
                "identity", False,
                "signature over challenge does not verify as Ed25519 "
                "(pseudo-signature, e.g. HMAC or hash stub?)")
        if not verify_signature(key_hex, p2, sig2):
            return self._record("identity", False, "second challenge signature invalid")
        if verify_signature(key_hex, p2, sig1):
            return self._record("identity", False, "signature does not bind to payload")
        return self._record("identity", True, "Ed25519 key valid; challenge signatures verify and bind")

    # ── 2. Mutual handshake ──────────────────────────────────────────────

    def check_handshake(self) -> bool:
        try:
            m1 = self.core.handshake_init(self.me, self.peer_public)
            self._m1_replay = m1  # kept for the replay check
            status, m2 = _post(f"{self.base}/uahp/handshake/respond", m1)
            if status != 200:
                return self._record(
                    "handshake", False,
                    f"respond failed ({status}): {m2.get('error', '?')}")
            m3 = self.core.handshake_finalize(self.me, m2)
            status, done = _post(f"{self.base}/uahp/handshake/complete", m3)
            if status != 200 or not done.get("success"):
                return self._record("handshake", False, "completion failed")
        except HandshakeError as e:
            return self._record("handshake", False, str(e))
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            return self._record("handshake", False, f"protocol error: {e}")

        session = self.core.get_session(done.get("session_token", ""))
        if session is None:
            return self._record("handshake", False, "no local session established")
        digest = hashlib.sha256(session.shared_secret).hexdigest()
        if digest != done.get("secret_sha256"):
            return self._record("handshake", False, "shared secret digests DIFFER")
        return self._record(
            "handshake", True,
            "mutual 3-message handshake complete; both signatures verified; "
            "shared secret digests match")

    # ── 3. Signed receipts ───────────────────────────────────────────────

    def check_receipts(self) -> bool:
        mine = self.core.create_receipt(
            self.me, "verify-task", "compliance_probe", True,
            input_data="probe", output_data="probe",
        )
        status, ack = _post(f"{self.base}/uahp/receipt",
                            {"receipt": mine.to_dict(),
                             "public_key": self.me.public_key})
        if status != 200 or not ack.get("verified"):
            return self._record("receipts", False, "agent did not verify our signed receipt")
        try:
            theirs = Receipt(**ack["receipt"])
        except (KeyError, TypeError):
            return self._record("receipts", False, "agent returned no receipt of its own")
        if not self.core.verify_receipt(theirs, ack.get("public_key", "")):
            return self._record("receipts", False, "agent's receipt signature does not verify")

        # The agent must REJECT a tampered receipt.
        tampered = mine.to_dict()
        tampered["success"] = not tampered["success"]  # body changed, signature stale
        status, resp = _post(f"{self.base}/uahp/receipt",
                             {"receipt": tampered, "public_key": self.me.public_key})
        if status == 200 and resp.get("verified"):
            return self._record(
                "receipts", False,
                "agent ACCEPTED a tampered receipt (no real verification)")
        return self._record(
            "receipts", True,
            "receipts verify both directions; tampered receipt rejected")

    # ── 4. Replay protection ─────────────────────────────────────────────

    def check_replay(self) -> bool:
        m1 = getattr(self, "_m1_replay", None)
        if m1 is None:
            return self._record("replay", False, "no handshake opening to replay")
        status, resp = _post(f"{self.base}/uahp/handshake/respond", m1)
        if status == 200:
            return self._record(
                "replay", False,
                "agent ACCEPTED a replayed handshake opening (same nonce)")
        return self._record(
            "replay", True,
            f"replayed opening refused ({status}): {resp.get('error', 'rejected')}")

    # ── 5. Revocation honored (destructive) ──────────────────────────────

    def check_revocation(self) -> bool:
        status, dead = _post(f"{self.base}/uahp/die",
                             {"reason": "compliance verification",
                              "declared_by": self.me.agent_id})
        if status != 200:
            return self._record("revocation", False, "agent refused to issue a death certificate")
        try:
            cert = DeathCertificate(**dead["certificate"])
        except (KeyError, TypeError):
            return self._record("revocation", False, "malformed death certificate")
        if not UAHPCore.verify_death_certificate(cert):
            return self._record("revocation", False, "death certificate signature invalid")

        status, resp = _post(f"{self.base}/uahp/sign",
                             {"payload": "post-death challenge"})
        if status == 200 and resp.get("signed"):
            return self._record(
                "revocation", False,
                "agent SIGNED after issuing its own death certificate "
                "(revocation not enforced)")
        return self._record(
            "revocation", True,
            "death certificate verifies; post-death signing refused: "
            f"{resp.get('refusal', 'rejected')}")

    # ── 6. Honest crypto_mode ────────────────────────────────────────────

    def check_crypto_mode(self) -> bool:
        declared = (self.peer_public or {}).get("metadata", {}).get(
            "crypto_mode", "classical")
        if declared.startswith("hybrid"):
            # This HTTP surface ran a classical Ed25519+X25519 handshake;
            # a hybrid claim here is not backed by what actually executed.
            return self._record(
                "crypto_mode", False,
                f"declares '{declared}' but served a classical handshake "
                "(no KEM material on the wire)")
        return self._record(
            "crypto_mode", True,
            f"declares '{declared}', matching the classical Ed25519+X25519 "
            "handshake that actually ran")

    # ── Runner ───────────────────────────────────────────────────────────

    def run(self) -> List[CheckResult]:
        self.check_identity()
        if self.peer_public is None:  # unreachable: nothing else can run
            return self.results
        self.check_handshake()
        self.check_receipts()
        self.check_replay()
        self.check_crypto_mode()
        self.check_revocation()  # destructive: keep last
        return self.results


def verify_agent(base_url: str) -> List[CheckResult]:
    return AgentVerifier(base_url).run()
