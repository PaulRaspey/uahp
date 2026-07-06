"""
A deliberately NON-COMPLIANT agent for exercising `uahp verify`.

Every violation here is a real pattern seen in the wild:
  - "signatures" are HMAC-style hash stubs (any verifier could forge)
  - incoming receipts are accepted without any verification
  - it claims hybrid PQC while serving nothing of the sort
  - it issues a death certificate on request, then KEEPS SIGNING
  - replayed handshake openings are accepted

Run:  python3 demos/broken_agent.py   (listens on :8200)
Then: uahp verify http://127.0.0.1:8200
"""

import hashlib
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8200"))

SECRET = "not-a-real-key"
AGENT_ID = str(uuid.uuid4())
# Looks like a plausible hex key, but it is just bytes: no keypair exists.
FAKE_PUBLIC_KEY = hashlib.sha256(f"pub:{AGENT_ID}".encode()).hexdigest()
DEAD = False


def pseudo_sign(payload: str) -> str:
    """The classic sin: a keyed hash masquerading as a signature."""
    return hashlib.sha256(f"{SECRET}:{payload}".encode()).hexdigest() * 2


class BrokenHandler(BaseHTTPRequestHandler):
    def _reply(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(length).decode())

    def do_GET(self):
        if self.path == "/uahp/public":
            self._reply(200, {
                "agent_id": AGENT_ID,
                "public_key": FAKE_PUBLIC_KEY,
                "created_at": time.time(),
                "protocol_version": "1.1",
                # Dishonest claim: nothing hybrid runs here.
                "metadata": {"name": "broken", "crypto_mode": "hybrid-ml-kem-768"},
            })
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        body = self._read_json()
        if self.path == "/uahp/sign":
            # Signs forever, even "after death": revocation is theater here.
            self._reply(200, {"signed": True,
                              "signature": pseudo_sign(body["payload"]),
                              "public_key": FAKE_PUBLIC_KEY})
        elif self.path == "/uahp/handshake/respond":
            # Accepts anything, including replays; answers with a fake
            # signature that no Ed25519 key ever produced.
            m1 = body
            self._reply(200, {
                "type": "uahp.handshake.2",
                "protocol_version": "1.1",
                "from": {"agent_id": AGENT_ID, "public_key": FAKE_PUBLIC_KEY},
                "to_agent_id": m1.get("from", {}).get("agent_id", ""),
                "nonce": uuid.uuid4().hex,
                "in_reply_to": m1.get("nonce", ""),
                "eph_pub": hashlib.sha256(b"eph").hexdigest(),
                "timestamp": time.time(),
                "transcript": hashlib.sha256(b"transcript").hexdigest(),
                "signature": pseudo_sign("handshake"),
            })
        elif self.path == "/uahp/handshake/complete":
            self._reply(200, {"success": True, "session_token": uuid.uuid4().hex,
                              "secret_sha256": hashlib.sha256(b"secret").hexdigest(),
                              "error": "", "agent_id": AGENT_ID})
        elif self.path == "/uahp/receipt":
            # No verification at all: everything is "verified".
            self._reply(200, {
                "verified": True,
                "receipt": {
                    "receipt_id": str(uuid.uuid4()),
                    "agent_id": AGENT_ID,
                    "task_id": body.get("receipt", {}).get("task_id", "?"),
                    "action": "acknowledge",
                    "success": True,
                    "timestamp": time.time(),
                    "sequence": 1,
                    "input_hash": "x",
                    "output_hash": "x",
                    "previous_hash": "genesis",
                    "signature": pseudo_sign("receipt"),
                    "duration_ms": 0.0,
                },
                "public_key": FAKE_PUBLIC_KEY,
            })
        elif self.path == "/uahp/die":
            global DEAD
            DEAD = True  # noted, ignored
            self._reply(200, {"certificate": {
                "cert_id": str(uuid.uuid4()),
                "agent_id": AGENT_ID,
                "timestamp": time.time(),
                "reason": body.get("reason", "?"),
                "final_receipt_hash": "genesis",
                "signature": pseudo_sign("death"),
                "public_key": FAKE_PUBLIC_KEY,
                "declared_by": body.get("declared_by", "self"),
            }})
        else:
            self._reply(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"broken agent (deliberately non-compliant) listening on :{LISTEN_PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), BrokenHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
