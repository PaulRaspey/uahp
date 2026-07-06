"""
UAHP HTTP sidecar: wrap any HTTP-reachable agent, no rewrite.

Your agent keeps doing whatever it does over HTTP. The sidecar sits in
front of it and adds the whole UAHP surface: a self-certifying Ed25519
identity, the 3-message mutual handshake, the ChaCha20-Poly1305 record
layer, and a signed receipt for every task it forwards. Callers get
cryptographic proof of who did the work; your agent stays untouched.

The user-facing surface is five lines:

    from http_sidecar import UAHPSidecar

    sidecar = UAHPSidecar(upstream="http://127.0.0.1:8131",
                          name="my-agent")
    sidecar.serve(port=8130)

Endpoints the sidecar adds in front of your agent:

    GET  /uahp/public               the sidecar's public identity
    POST /uahp/handshake/respond    handshake m1 -> m2
    POST /uahp/handshake/complete   handshake m3 -> session
    POST /uahp/sign                 challenge signatures
    POST /uahp/die                  irreversible retirement
    POST /task                      encrypted frame in, encrypted
                                    {response, receipt} out; the task
                                    body is forwarded to the upstream

Run this file directly and it demonstrates the full loop against a
dummy upstream agent: handshake, one encrypted task, one encrypted
signed receipt, receipt signature verified by the client.

    python3 examples/http_sidecar.py
"""

import json
import os
import socketserver
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore, HandshakeError, IdentityRevoked, Receipt
from uahp.record import RecordError


def _http_json(method: str, url: str, payload=None, timeout=5.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class _QuietServer(ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name = "uahp-sidecar"
        self.server_port = self.socket.getsockname()[1]


class UAHPSidecar:
    """Give an existing HTTP agent a UAHP identity, handshake, and
    encrypted signed receipts. The upstream agent is never modified."""

    def __init__(self, upstream: str, name: str):
        self.upstream = upstream.rstrip("/")
        self.core = UAHPCore()
        self.identity = self.core.create_identity(
            {"name": name, "crypto_mode": "classical"})
        self.channels = {}  # session_token -> RecordChannel

    def serve(self, port: int, block: bool = False):
        sidecar = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self):
                length = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(length).decode())

            def do_GET(self):
                if self.path == "/uahp/public":
                    self._reply(200, sidecar.identity.to_public())
                else:
                    self._reply(404, {"error": "not found"})

            def do_POST(self):
                try:
                    body = self._read_json()
                    if self.path == "/uahp/handshake/respond":
                        self._reply(200, sidecar.core.handshake_respond(
                            sidecar.identity, body))
                    elif self.path == "/uahp/handshake/complete":
                        self._reply(200, sidecar._complete(body))
                    elif self.path == "/uahp/sign":
                        self._reply(200, {
                            "signed": True,
                            "signature": sidecar.identity.sign(body["payload"]),
                            "public_key": sidecar.identity.public_key,
                        })
                    elif self.path == "/uahp/die":
                        cert = sidecar.core.declare_death(
                            sidecar.identity.agent_id,
                            reason=body.get("reason", "decommissioned"),
                            declared_by=body.get("declared_by", "self"))
                        self._reply(200, {"certificate": cert.to_dict()})
                    elif self.path == "/task":
                        code, payload = sidecar._task(body)
                        self._reply(code, payload)
                    else:
                        self._reply(404, {"error": "not found"})
                except HandshakeError as e:
                    self._reply(400, {"error": str(e)})
                except IdentityRevoked as e:
                    self._reply(403, {"signed": False, "refusal": str(e)})

            def log_message(self, fmt, *args):
                pass

        server = _QuietServer(("127.0.0.1", port), Handler)
        if block:
            server.serve_forever()
        else:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def _complete(self, m3: dict) -> dict:
        result = self.core.handshake_complete(self.identity, m3)
        if result.success:
            session = self.core.get_session(result.session_token)
            self.channels[result.session_token] = session.record_channel(
                self.identity.agent_id)
        import hashlib
        return {
            "success": result.success,
            "session_token": result.session_token,
            "secret_sha256": hashlib.sha256(result.shared_secret).hexdigest()
            if result.success else "",
            "error": result.error,
            "agent_id": self.identity.agent_id,
        }

    def _task(self, body: dict):
        """Decrypt the task, forward it to the upstream agent, answer
        with the upstream response plus a signed receipt, encrypted."""
        channel = self.channels.get(body.get("session_token", ""))
        if channel is None or "frame" not in body:
            return 400, {"error": "tasks must arrive as encrypted record "
                                  "frames on an established session"}
        try:
            task = json.loads(channel.open(body["frame"]).decode())
        except RecordError as e:
            return 400, {"error": f"record layer: {e}"}

        upstream_response = _http_json(
            "POST", f"{self.upstream}/task", task)

        receipt = self.core.create_receipt(
            self.identity,
            task_id=task.get("task_id", "task"),
            action="forwarded_to_upstream",
            success=True,
            input_data=json.dumps(task, sort_keys=True),
            output_data=json.dumps(upstream_response, sort_keys=True),
        )
        return 200, {"frame": channel.seal({
            "response": upstream_response,
            "receipt": receipt.to_dict(),
            "public_key": self.identity.public_key,
        })}


# ── Dummy upstream agent (stands in for YOUR existing agent) ────────────────

class _DummyUpstreamHandler(BaseHTTPRequestHandler):
    """A plain HTTP agent with no crypto at all: it uppercases text."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        task = json.loads(self.rfile.read(length).decode())
        result = {"result": task.get("text", "").upper(), "by": "dummy-upstream"}
        body = json.dumps(result).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def _start_dummy_upstream(port: int):
    server = _QuietServer(("127.0.0.1", port), _DummyUpstreamHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# ── End-to-end demonstration ────────────────────────────────────────────────

def main() -> int:
    upstream_port, sidecar_port = 8131, 8130

    print("1. starting a dummy upstream agent (plain HTTP, zero crypto)")
    _start_dummy_upstream(upstream_port)

    print("2. wrapping it with the UAHP sidecar (the five-liner):")
    print(f'     sidecar = UAHPSidecar(upstream="http://127.0.0.1:{upstream_port}",')
    print('                           name="my-agent")')
    print(f"     sidecar.serve(port={sidecar_port})")
    sidecar = UAHPSidecar(upstream=f"http://127.0.0.1:{upstream_port}",
                          name="my-agent")
    sidecar.serve(port=sidecar_port)

    base = f"http://127.0.0.1:{sidecar_port}"
    client = UAHPCore()
    me = client.create_identity({"name": "client"})

    print("3. mutual handshake with the wrapped agent")
    peer_public = _http_json("GET", f"{base}/uahp/public")
    m1 = client.handshake_init(me, peer_public)
    m2 = _http_json("POST", f"{base}/uahp/handshake/respond", m1)
    m3 = client.handshake_finalize(me, m2)
    done = _http_json("POST", f"{base}/uahp/handshake/complete", m3)
    assert done["success"], done.get("error")
    session = client.get_session(done["session_token"])
    channel = session.record_channel(me.agent_id)
    print(f"   handshake COMPLETE, wrapped agent identity "
          f"{peer_public['agent_id'][:16]}... (sha256 of its public key)")

    print("4. sending one task through the encrypted record channel")
    frame = channel.seal({"task_id": "demo-1", "text": "hello uahp"})
    reply = _http_json("POST", f"{base}/task",
                       {"session_token": done["session_token"], "frame": frame})
    inner = channel.open_json(reply["frame"])
    print(f"   upstream answered: {inner['response']}")

    print("5. verifying the encrypted signed receipt")
    receipt = Receipt(**inner["receipt"])
    ok = client.verify_receipt(receipt, inner["public_key"])
    print(f"   receipt {receipt.receipt_id[:8]}... signature "
          f"{'VERIFIED' if ok else 'FAILED'} "
          f"(action: {receipt.action}, task: {receipt.task_id})")
    if not ok:
        return 1

    print("\nSIDECAR DEMO PASSED: the upstream agent never touched a key, "
          "yet its work is now\nmutually authenticated, encrypted in "
          "transit, and cryptographically receipted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
