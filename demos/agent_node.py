"""
UAHP agent node: the docker-compose entrypoint for B6.

Each node creates a real Ed25519 identity, registers with the UAHP
registry, and exposes the responder half of the mutual handshake over
HTTP. The initiator node discovers its peer through the registry and
runs the full 3-message mutual handshake against it. Both sides derive
the same X25519+HKDF shared secret; the initiator proves it by
comparing secret digests.

Environment:
    AGENT_NAME     this node's name (e.g. alice)
    ROLE           initiator | responder
    PEER_NAME      peer to discover (initiator only)
    REGISTRY_URL   e.g. http://registry:8001
    AGENT_HOST     hostname peers can reach us at (compose service name)
    LISTEN_PORT    HTTP port for handshake endpoints (default 8100)
"""

import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore, HandshakeError

AGENT_NAME = os.environ.get("AGENT_NAME", "agent")
ROLE = os.environ.get("ROLE", "responder")
PEER_NAME = os.environ.get("PEER_NAME", "")
REGISTRY_URL = os.environ.get("REGISTRY_URL", "http://localhost:8001")
AGENT_HOST = os.environ.get("AGENT_HOST", "localhost")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8100"))
DEADLINE_SECONDS = 60.0

core = UAHPCore()
identity = core.create_identity({"name": AGENT_NAME})
START = time.time()


def log(msg: str) -> None:
    print(f"[{AGENT_NAME} +{time.time() - START:5.1f}s] {msg}", flush=True)


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
            else:
                self._reply(404, {"error": "not found"})
        except HandshakeError as e:
            self._reply(400, {"error": str(e)})

    def log_message(self, fmt, *args):  # silence default request logging
        pass


def serve() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), HandshakeHandler)
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

    peer_public = http_json("GET", public_url)
    log(f"fetched peer public identity {peer_public['agent_id'][:12]}...")

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
