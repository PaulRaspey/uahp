"""
UAHP Two-Process Handshake Test
================================
Proves mutual authentication across two REAL OS processes, not two
objects sharing memory. The parent process is the initiator (Alice);
a spawned child process is the responder (Bob). Every handshake
message crosses the process boundary as a JSON line over a pipe.

What this proves:
  1. Handshake messages survive real serialization (JSON over a pipe).
  2. Each side verifies the OTHER side's Ed25519 signature with no
     shared memory, no shared UAHPCore, no shared key material.
  3. Both processes independently derive the SAME 32-byte shared
     secret (compared by SHA-256 digest across the boundary).

Run: python3 test_two_process.py
"""

import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore


def _send(pipe, obj):
    pipe.write(json.dumps(obj) + "\n")
    pipe.flush()


def _recv(pipe):
    line = pipe.readline()
    if not line:
        raise RuntimeError("peer process closed the pipe")
    return json.loads(line)


def responder_main():
    """Child process: Bob. Speaks JSON lines on stdin/stdout."""
    core = UAHPCore()
    bob = core.create_identity({"name": "Bob", "process": str(os.getpid())})

    _send(sys.stdout, {"type": "hello", "public": bob.to_public()})

    m1 = _recv(sys.stdin)
    m2 = core.handshake_respond(bob, m1)
    _send(sys.stdout, m2)

    m3 = _recv(sys.stdin)
    result = core.handshake_complete(bob, m3)

    _send(sys.stdout, {
        "type": "done",
        "success": result.success,
        "session_token": result.session_token,
        "secret_sha256": hashlib.sha256(result.shared_secret).hexdigest(),
        "pid": os.getpid(),
    })


def initiator_main():
    """Parent process: Alice. Spawns Bob and runs the handshake."""
    print("UAHP Two-Process Handshake Test")
    print("=" * 60)

    child = subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "responder"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    failures = 0

    def check(name, condition):
        nonlocal failures
        if condition:
            print(f"  PASS  {name}")
        else:
            failures += 1
            print(f"  FAIL  {name}")

    try:
        core = UAHPCore()
        alice = core.create_identity({"name": "Alice", "process": str(os.getpid())})

        hello = _recv(child.stdout)
        check("responder announced itself from another process",
              hello["type"] == "hello" and "public_key" in hello["public"])

        m1 = core.handshake_init(alice, hello["public"])
        _send(child.stdin, m1)

        m2 = _recv(child.stdout)
        m3 = core.handshake_finalize(alice, m2)  # verifies Bob's signature
        _send(child.stdin, m3)

        done = _recv(child.stdout)               # Bob verified Alice's signature
        check("responder completed the handshake", done["success"])
        check("responder really is a different OS process",
              done["pid"] != os.getpid())

        session = core.get_session(done["session_token"])
        check("initiator holds the same session token", session is not None)
        check("both processes derived the SAME shared secret",
              session is not None
              and hashlib.sha256(session.shared_secret).hexdigest()
              == done["secret_sha256"])
    finally:
        child.stdin.close()
        child.wait(timeout=10)

    print("=" * 60)
    print(("ALL PASSED" if failures == 0 else f"{failures} FAILED")
          + " — mutual Ed25519 authentication across two OS processes")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "responder":
        responder_main()
    else:
        initiator_main()
