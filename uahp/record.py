"""
UAHP record layer v1.

Turns the handshake's HKDF shared secret into actual traffic protection:
ChaCha20-Poly1305 AEAD (from the cryptography library already in our
dependencies) over JSON frames.

Design:
- Per-direction keys derived from the session secret via HKDF with
  distinct info labels, so the two directions never share a nonce space.
- Counter-based 96-bit nonces per direction, starting at 0, strictly
  incrementing, never reused. A receiver rejects any frame whose
  sequence does not advance (replays and out-of-order both fail).
- Frame format: {"v": 1, "seq": n, "nonce": hex, "ciphertext": hex}
  where ciphertext is the AEAD output over the serialized payload with
  the frame header as associated data.

Author: Paul Raspey
License: MIT
"""

import json

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RECORD_VERSION = 1
INFO_INITIATOR = b"uahp record v1 initiator"
INFO_RESPONDER = b"uahp record v1 responder"
NONCE_BYTES = 12


class RecordError(Exception):
    """Raised when a record frame is malformed, tampered, replayed,
    out of order, or from the wrong protocol version."""


def _derive_key(shared_secret: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)


class RecordChannel:
    """
    One end of an encrypted record channel over a completed handshake.

    The initiator sends with the initiator-labeled key and receives with
    the responder-labeled key; the responder does the opposite. Both ends
    derive both keys from the same session secret, so no extra key
    exchange happens here.
    """

    def __init__(self, shared_secret: bytes, role: str):
        if role not in ("initiator", "responder"):
            raise ValueError("role must be 'initiator' or 'responder'")
        if not shared_secret:
            raise ValueError("shared_secret must be non-empty")
        key_i = _derive_key(shared_secret, INFO_INITIATOR)
        key_r = _derive_key(shared_secret, INFO_RESPONDER)
        send_key, recv_key = (key_i, key_r) if role == "initiator" else (key_r, key_i)
        self.role = role
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)
        self._send_seq = 0
        self._next_recv_seq = 0

    @classmethod
    def for_session(cls, session, agent_id: str) -> "RecordChannel":
        """Build the channel for one party of a core Session object."""
        if agent_id == session.agent_a_id:
            role = "initiator"
        elif agent_id == session.agent_b_id:
            role = "responder"
        else:
            raise RecordError(
                f"agent {agent_id[:8]} is not a party to this session"
            )
        return cls(session.shared_secret, role)

    # ── Sending ──────────────────────────────────────────────────────────

    def seal(self, payload) -> dict:
        """Encrypt a payload (dict, str, or bytes) into a record frame."""
        if isinstance(payload, (dict, list)):
            plaintext = json.dumps(payload, sort_keys=True).encode()
        elif isinstance(payload, str):
            plaintext = payload.encode()
        else:
            plaintext = payload

        seq = self._send_seq
        nonce = seq.to_bytes(NONCE_BYTES, "big")
        header = {"v": RECORD_VERSION, "seq": seq, "nonce": nonce.hex()}
        aad = json.dumps(header, sort_keys=True).encode()
        ciphertext = self._send.encrypt(nonce, plaintext, aad)
        self._send_seq += 1
        return {
            "v": RECORD_VERSION,
            "seq": seq,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }

    # ── Receiving ────────────────────────────────────────────────────────

    def open(self, frame: dict) -> bytes:
        """Authenticate and decrypt a record frame. Raises RecordError."""
        try:
            version = frame["v"]
            seq = int(frame["seq"])
            nonce = bytes.fromhex(frame["nonce"])
            ciphertext = bytes.fromhex(frame["ciphertext"])
        except (KeyError, TypeError, ValueError) as e:
            raise RecordError(f"malformed record frame: {e}")

        if version != RECORD_VERSION:
            raise RecordError(f"unsupported record version {version}")
        if seq != self._next_recv_seq:
            raise RecordError(
                f"sequence does not advance: got {seq}, "
                f"expected {self._next_recv_seq}"
            )
        if nonce != seq.to_bytes(NONCE_BYTES, "big"):
            raise RecordError("nonce does not match sequence counter")

        header = {"v": version, "seq": seq, "nonce": frame["nonce"]}
        aad = json.dumps(header, sort_keys=True).encode()
        try:
            plaintext = self._recv.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise RecordError(
                "AEAD authentication failed (tampered ciphertext or wrong key)"
            )
        self._next_recv_seq += 1
        return plaintext

    def open_json(self, frame: dict) -> dict:
        """open() plus JSON decoding, for dict payloads."""
        return json.loads(self.open(frame).decode())
