"""
UAHP reference demo, one command:

    python3 demos/run_demo.py

Spawns three real OS processes on localhost:
    registry   FastAPI discovery service (port 8001)
    bob        responder agent node      (port 8100)
    alice      initiator agent node      (port 8101)

Alice discovers Bob through the registry and runs the full narrative:
mutual handshake, signed receipt exchange, Bob's death certificate,
and the live rejection of Bob's post-death signature.

Requires the registry extra:  pip install -e ".[registry]"
"""

import os
import signal
import subprocess
import sys
import tempfile
import threading

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT_NODE = os.path.join(REPO, "demos", "agent_node.py")
REGISTRY_PORT = "8001"


def stream(proc: subprocess.Popen, prefix: str) -> None:
    for line in proc.stdout:
        sys.stdout.write(f"{prefix} {line.decode(errors='replace')}")
        sys.stdout.flush()


def main() -> int:
    try:
        import fastapi, sqlalchemy, uvicorn  # noqa: F401
    except ImportError:
        print('The registry needs extras: pip install -e ".[registry]"')
        return 1

    db_path = os.path.join(tempfile.mkdtemp(prefix="uahp-demo-"), "registry.db")
    env_base = {**os.environ, "PYTHONUNBUFFERED": "1"}
    procs = []

    def spawn(args, prefix, extra_env=None):
        proc = subprocess.Popen(
            args, cwd=REPO, env={**env_base, **(extra_env or {})},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        procs.append(proc)
        threading.Thread(target=stream, args=(proc, prefix), daemon=True).start()
        return proc

    print("=" * 64)
    print("UAHP reference demo: three processes, one protocol")
    print("=" * 64)

    spawn(
        [sys.executable, "-m", "uvicorn", "uahp.registry.main:app",
         "--host", "127.0.0.1", "--port", REGISTRY_PORT, "--log-level", "warning"],
        "[registry ]",
        {"UAHP_REGISTRY_DB": f"sqlite:///{db_path}"},
    )
    spawn(
        [sys.executable, AGENT_NODE], "[bob      ]",
        {"AGENT_NAME": "bob", "ROLE": "responder",
         "REGISTRY_URL": f"http://127.0.0.1:{REGISTRY_PORT}",
         "AGENT_HOST": "127.0.0.1", "LISTEN_PORT": "8100"},
    )
    alice = spawn(
        [sys.executable, AGENT_NODE], "[alice    ]",
        {"AGENT_NAME": "alice", "ROLE": "initiator", "PEER_NAME": "bob",
         "REGISTRY_URL": f"http://127.0.0.1:{REGISTRY_PORT}",
         "AGENT_HOST": "127.0.0.1", "LISTEN_PORT": "8101"},
    )

    try:
        code = alice.wait(timeout=90)
    except subprocess.TimeoutExpired:
        print("[demo     ] FATAL: initiator did not finish within 90s")
        code = 1
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    print("=" * 64)
    print(f"demo {'PASSED' if code == 0 else 'FAILED'} (initiator exit {code})")
    return code


if __name__ == "__main__":
    sys.exit(main())
