"""
UAHP agent node: the reference demo and docker-compose entrypoint.

Each node creates a real Ed25519 identity, registers with the UAHP
registry, and serves the protocol over HTTP. The initiator discovers
its peer through the registry and runs the full narrative:

  1. HANDSHAKE   3-message mutual authentication, signatures verified
                 both directions, same X25519+HKDF secret on both sides
  2. RECEIPTS    each side issues a signed work receipt; each side
                 verifies the other's receipt signature
  3. DEATH       the responder issues its own death certificate and
                 destroys its private key
  4. REJECTION   the responder refuses to sign post-death, and the
                 initiator independently rejects post-death material
                 and refuses any new handshake with the dead agent

Environment:
    AGENT_NAME     this node's name (e.g. alice)
    ROLE           initiator | responder
    PEER_NAME      peer to discover (initiator only)
    REGISTRY_URL   e.g. http://registry:8001
    AGENT_HOST     hostname peers can reach us at (compose service name)
    LISTEN_PORT    HTTP port for protocol endpoints (default 8100)
"""

import hashlib
import json
import os
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import (
    UAHPCore, HandshakeError, IdentityRevoked, Receipt, DeathCertificate,
)

AGENT_NAME = os.environ.get("AGENT_NAME", "agent")
ROLE = os.environ.get("ROLE", "responder")
PEER_NAME = os.environ.get("PEER_NAME", "")
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://localhost:8001")
AGENT_HOST = os.environ.get("AGENT_HOST", "localhost")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8100"))
DEADLINE_SECONDS = 60.0
# Seconds to pause before each act, for screen recording. 0 = full speed.
DEMO_PACE = float(os.environ.get("DEMO_PACE", "0"))

core = UAHPCore()
identity = core.create_identity({"name": AGENT_NAME, "crypto_mode": "classical"})
START = time.time()


def log(msg: str) -> None:
    print(f"[{AGENT_NAME} +{time.time() - START:5.1f}s] {msg}", flush=True)


def act(title: str) -> None:
    if DEMO_PACE:
        time.sleep(DEMO_PACE)
    log(f"────── {title} ──────")


def http_json(method: str, url: str, payload=None, timeout=5.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ── Responder HTTP surface ───────────────────────────────────────────────────

class HandshakeHandler(BaseHTTPRequestHandler):
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
            self._reply(200, identity.to_public())
        else:
            self._reply(404, {"error": "not found"})

    def do_POST(self):
        try:
            if self.path == "/uahp/handshake/respond":
                m1 = self._read_json()
                m2 = core.handshake_respond(identity, m1)
                log(f"m1 received, initiator signature VERIFIED; sent m2")
                self._reply(200, m2)
            elif self.path == "/uahp/handshake/complete":
                m3 = self._read_json()
                result = core.handshake_complete(identity, m3)
                if result.success:
                    log(f"m3 received, mutual handshake COMPLETE "
                        f"(session {result.session_token[:16]}...)")
                self._reply(200, {
                    "success": result.success,
                    "session_token": result.session_token,
                    "secret_sha256": hashlib.sha256(result.shared_secret).hexdigest()
                    if result.success else "",
                    "error": result.error,
                    "agent_id": identity.agent_id,
                })
            elif self.path == "/uahp/receipt":
                self._handle_receipt()
            elif self.path == "/uahp/sign":
                self._handle_sign()
            elif self.path == "/uahp/die":
                self._handle_die()
            else:
                self._reply(404, {"error": "not found"})
        except HandshakeError as e:
            self._reply(400, {"error": str(e)})

    def _handle_receipt(self):
        """Verify a peer's signed receipt; answer with our own."""
        body = self._read_json()
        peer_receipt = Receipt(**body["receipt"])
        verified = core.verify_receipt(peer_receipt, body["public_key"])
        log(f"receipt {peer_receipt.receipt_id[:8]}... from "
            f"{peer_receipt.agent_id[:8]}... signature "
            f"{'VERIFIED' if verified else 'REJECTED'}")
        if not verified:
            self._reply(400, {"verified": False})
            return
        try:
            mine = core.create_receipt(
                identity, peer_receipt.task_id, "acknowledge", True,
                input_data=peer_receipt.signature, output_data="ack",
            )
        except IdentityRevoked as e:
            self._reply(403, {"verified": True, "refusal": str(e)})
            return
        self._reply(200, {
            "verified": True,
            "receipt": mine.to_dict(),
            "public_key": identity.public_key,
        })

    def _handle_sign(self):
        """Sign an arbitrary payload, or refuse if this identity is revoked."""
        body = self._read_json()
        try:
            signature = identity.sign(body["payload"])
            log(f"signed payload for peer")
            self._reply(200, {"signed": True, "signature": signature,
                              "public_key": identity.public_key})
        except IdentityRevoked as e:
            log(f"sign request REFUSED: {e}")
            self._reply(403, {"signed": False, "refusal": str(e)})

    def _handle_die(self):
        """Issue our own death certificate. Irreversible."""
        body = self._read_json()
        cert = core.declare_death(
            identity.agent_id,
            reason=body.get("reason", "decommissioned"),
            declared_by=body.get("declared_by", "self"),
        )
        log("death certificate ISSUED; private key DESTROYED")
        self._reply(200, {"certificate": cert.to_dict()})

    def log_message(self, fmt, *args):  # silence default request logging
        pass


class AgentHTTPServer(ThreadingHTTPServer):
    def server_bind(self):
        # Skip http.server's reverse-DNS lookup (a multi-second stall on
        # some networks); bind directly and name ourselves.
        socketserver.TCPServer.server_bind(self)
        self.server_name = AGENT_NAME
        self.server_port = self.socket.getsockname()[1]


def serve() -> ThreadingHTTPServer:
    server = AgentHTTPServer(("0.0.0.0", LISTEN_PORT), HandshakeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log(f"handshake endpoint listening on :{LISTEN_PORT}")
    return server


# ── Registry client ──────────────────────────────────────────────────────────

def register_with_registry() -> None:
    base = f"http://{AGENT_HOST}:{LISTEN_PORT}"
    agent_id = f"uahp:{AGENT_NAME}:{identity.agent_id}"
    registration = {
        "agentId": agent_id,
        "expiresIn": 3600,
        "livenessProof": {"type": "startup", "timestamp": time.time()},
        "capabilities": [{
            "id": "uahp.handshake",
            "description": "UAHP mutual authentication (Ed25519 + X25519/HKDF)",
        }],
        "thermodynamicProfile": {
            "currentPressureScore": 0.1,
            "costPerJoule": 0.001,
            "carbonIntensity": 50,
        },
        "endpoints": {
            "public": f"{base}/uahp/public",
            "handshake": f"{base}/uahp/handshake",
        },
        "signature": identity.sign(f"register:{agent_id}"),
    }
    while time.time() - START < DEADLINE_SECONDS:
        try:
            resp = http_json("POST", f"{REGISTRY_URL}/registry/register", registration)
            log(f"registered with registry: {resp['status']} as {resp['agentId'][:24]}...")
            return
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(1.0)
    log("FATAL: could not reach registry before deadline")
    sys.exit(1)


def discover_peer(peer_name: str) -> dict:
    while time.time() - START < DEADLINE_SECONDS:
        try:
            results = http_json("GET", f"{REGISTRY_URL}/registry/discover")
            for entry in results:
                if entry["agentId"].startswith(f"uahp:{peer_name}:"):
                    log(f"discovered peer {entry['agentId'][:24]}... via registry")
                    return entry
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1.0)
    log(f"FATAL: peer {peer_name} not discovered before deadline")
    sys.exit(1)


# ── Initiator flow ───────────────────────────────────────────────────────────

def run_initiator() -> int:
    peer_entry = discover_peer(PEER_NAME)
    public_url = peer_entry["endpoints"]["public"]
    handshake_url = peer_entry["endpoints"]["handshake"]
    base_url = public_url.rsplit("/uahp/", 1)[0]

    peer_public = http_json("GET", public_url)
    log(f"fetched peer public identity {peer_public['agent_id'][:12]}...")

    act("ACT 1: MUTUAL HANDSHAKE (Ed25519 + X25519/HKDF)")
    m1 = core.handshake_init(identity, peer_public)
    m2 = http_json("POST", f"{handshake_url}/respond", m1)
    m3 = core.handshake_finalize(identity, m2)  # verifies responder signature
    log("m2 received, responder signature VERIFIED; sent m3")
    done = http_json("POST", f"{handshake_url}/complete", m3)

    if not done.get("success"):
        log(f"FATAL: handshake failed: {done.get('error')}")
        return 1

    session = core.get_session(done["session_token"])
    if session is None:
        log("FATAL: initiator has no matching session")
        return 1
    my_digest = hashlib.sha256(session.shared_secret).hexdigest()
    if my_digest != done["secret_sha256"]:
        log("FATAL: shared secret digests DIFFER")
        return 1

    elapsed = time.time() - START
    log(f"MUTUAL HANDSHAKE COMPLETE in {elapsed:.1f}s "
        f"(deadline {DEADLINE_SECONDS:.0f}s)")
    log(f"  session_token: {done['session_token']}")
    log(f"  shared secret sha256 matches on both nodes: {my_digest[:24]}...")
    if elapsed >= DEADLINE_SECONDS:
        log("FATAL: exceeded 60 second acceptance deadline")
        return 1

    act("ACT 2: SIGNED RECEIPT EXCHANGE")
    mine = core.create_receipt(
        identity, "demo-task-1", "completed_work", True,
        input_data="demo input", output_data="demo output",
    )
    log(f"issued signed receipt {mine.receipt_id[:8]}... for demo-task-1")
    ack = http_json("POST", f"{base_url}/uahp/receipt",
                    {"receipt": mine.to_dict(), "public_key": identity.public_key})
    if not ack.get("verified"):
        log("FATAL: peer rejected our receipt signature")
        return 1
    log(f"peer verified our receipt signature")
    peer_receipt = Receipt(**ack["receipt"])
    if not core.verify_receipt(peer_receipt, ack["public_key"]):
        log("FATAL: peer's receipt signature did not verify")
        return 1
    log(f"peer receipt {peer_receipt.receipt_id[:8]}... signature VERIFIED "
        f"(both directions signed and checked)")

    act("ACT 3: DEATH CERTIFICATE")
    dead = http_json("POST", f"{base_url}/uahp/die",
                     {"reason": "demo decommission",
                      "declared_by": identity.agent_id})
    cert = DeathCertificate(**dead["certificate"])
    if not UAHPCore.verify_death_certificate(cert):
        log("FATAL: death certificate did not verify")
        return 1
    core.record_death_certificate(cert)
    log(f"death certificate for {PEER_NAME} VERIFIED and recorded "
        f"(reason: {cert.reason})")

    act("ACT 4: POST-DEATH REJECTION, LIVE")
    failures = 0

    # 4a. The dead agent itself refuses to sign (key destroyed).
    try:
        refusal = http_json("POST", f"{base_url}/uahp/sign",
                            {"payload": "post-death message"})
        log(f"FATAL: dead peer signed! {refusal}")
        failures += 1
    except urllib.error.HTTPError as e:
        detail = json.loads(e.read().decode())
        log(f"{PEER_NAME} REFUSED to sign post-death: {detail['refusal']}")

    # 4b. This node independently rejects post-death material, even
    # though the signature bytes themselves are valid Ed25519.
    forged = Receipt(**{**peer_receipt.to_dict(),
                        "timestamp": cert.timestamp + 100000})
    if core.verify_receipt(forged, ack["public_key"]):
        log("FATAL: post-death-timestamped receipt verified!")
        failures += 1
    else:
        log(f"REJECTED post-death-timestamped receipt from {PEER_NAME}: "
            f"identity is revoked")

    # 4c. New handshakes with the dead agent are refused outright.
    try:
        core.handshake_init(identity, peer_public)
        log("FATAL: handshake with dead agent was allowed!")
        failures += 1
    except HandshakeError as e:
        log(f"REFUSED new handshake with dead agent: {e}")

    if failures:
        return 1
    log("DEMO COMPLETE: handshake, signed receipts, death certificate, "
        "and live post-death rejection, all cryptographically enforced")
    return 0


def main() -> int:
    log(f"identity {identity.agent_id[:12]}... pubkey {identity.public_key[:16]}...")
    serve()
    register_with_registry()

    if ROLE == "initiator":
        return run_initiator()

    log("responder ready; serving handshakes")
    try:
        while True:
            time.sleep(30)
            try:
                http_json("POST", f"{REGISTRY_URL}/registry/heartbeat",
                          {"agentId": f"uahp:{AGENT_NAME}:{identity.agent_id}"})
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
