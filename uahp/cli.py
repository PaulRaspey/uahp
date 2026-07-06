"""
UAHP command line interface.

Commands:
    uahp init     Create a local agent identity (Ed25519 keypair)
    uahp status   Show the local agent identity and key health
    uahp verify   Prove the local identity can sign and verify
    uahp run      Start the UAHP MCP server (JSON-RPC 2.0 over stdio)

Author: Paul Raspey
License: MIT
"""

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import PROTOCOL_VERSION, verify_signature

UAHP_DIR = Path.home() / ".uahp"
IDENTITY_FILE = UAHP_DIR / "identity.json"


def _load_identity() -> dict:
    if not IDENTITY_FILE.exists():
        print(f"No identity found at {IDENTITY_FILE}. Run: uahp init", file=sys.stderr)
        sys.exit(1)
    return json.loads(IDENTITY_FILE.read_text())


def cmd_init(args) -> int:
    if IDENTITY_FILE.exists() and not args.force:
        identity = json.loads(IDENTITY_FILE.read_text())
        print(f"Identity already exists: {identity['agent_id']}")
        print("Use 'uahp init --force' to replace it (the old key is destroyed).")
        return 0

    private_key = Ed25519PrivateKey.generate()
    pub_raw = private_key.public_key().public_bytes_raw()
    identity = {
        "agent_id": hashlib.sha256(pub_raw).hexdigest(),
        "public_key": pub_raw.hex(),
        "private_key": private_key.private_bytes_raw().hex(),
        "created_at": time.time(),
        "protocol_version": PROTOCOL_VERSION,
    }

    UAHP_DIR.mkdir(mode=0o700, exist_ok=True)
    IDENTITY_FILE.write_text(json.dumps(identity, indent=2))
    IDENTITY_FILE.chmod(0o600)

    print("UAHP identity created (Ed25519).")
    print(f"  agent_id:   {identity['agent_id']}")
    print(f"  public_key: {identity['public_key']}")
    print(f"  stored at:  {IDENTITY_FILE}")
    return 0


def cmd_status(args) -> int:
    identity = _load_identity()
    print("UAHP local identity")
    print(f"  agent_id:         {identity['agent_id']}")
    print(f"  public_key:       {identity['public_key']}")
    print(f"  protocol_version: {identity.get('protocol_version', '?')}")
    print(f"  created_at:       {time.ctime(identity.get('created_at', 0))}")

    try:
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(identity["private_key"])
        )
        derived_pub = private_key.public_key().public_bytes_raw().hex()
        key_ok = derived_pub == identity["public_key"]
    except (KeyError, ValueError):
        key_ok = False
    print(f"  key health:       {'OK (private key matches public key)' if key_ok else 'BROKEN'}")
    return 0 if key_ok else 1


def cmd_verify(args) -> int:
    if args.agent:
        return _verify_remote_agent(args.agent)
    identity = _load_identity()
    failures = []

    # 1. agent_id must be the hash of the public key
    expected_id = hashlib.sha256(bytes.fromhex(identity["public_key"])).hexdigest()
    if expected_id != identity["agent_id"]:
        failures.append("agent_id does not match sha256(public_key)")

    # 2. The private key must produce signatures the public key verifies
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(identity["private_key"])
        )
        payload = f"uahp-verify:{identity['agent_id']}:{time.time()}"
        signature = private_key.sign(payload.encode()).hex()
        if not verify_signature(identity["public_key"], payload, signature):
            failures.append("signature did not verify against the public key")
    except (KeyError, ValueError) as e:
        failures.append(f"private key unusable: {e}")

    if failures:
        print("VERIFY FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("VERIFY OK")
    print(f"  agent_id derivation: sha256(public_key) matches")
    print(f"  Ed25519 sign/verify: round trip succeeded")
    return 0


def _verify_remote_agent(base_url: str) -> int:
    from .verifier import verify_agent

    print(f"UAHP compliance verification: {base_url}")
    print("(the revocation check is destructive: it retires the candidate)")
    print("-" * 64)
    results = verify_agent(base_url)
    failed = 0
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        failed += 0 if r.passed else 1
        print(f"  {mark}  {r.requirement:<12} {r.detail}")
    print("-" * 64)
    if failed:
        print(f"NOT COMPLIANT: {failed} of {len(results)} requirements failed")
        return 1
    print(f"UAHP COMPLIANT: all {len(results)} requirements passed")
    return 0


def cmd_run(args) -> int:
    from .mcp_server import main as mcp_main
    asyncio.run(mcp_main())
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="uahp",
        description="UAHP: identity, trust, and accountability for autonomous agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a local agent identity")
    p_init.add_argument("--force", action="store_true", help="Replace an existing identity")
    p_init.set_defaults(func=cmd_init)

    p_status = sub.add_parser("status", help="Show the local identity and key health")
    p_status.set_defaults(func=cmd_status)

    p_verify = sub.add_parser(
        "verify",
        help="Verify the local identity, or a running agent's UAHP compliance",
    )
    p_verify.add_argument(
        "agent", nargs="?", default=None,
        help="Base URL of a running agent to verify (e.g. http://127.0.0.1:8100). "
             "The revocation check retires the candidate agent.",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_run = sub.add_parser("run", help="Start the UAHP MCP server on stdio")
    p_run.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # The consumer closed the pipe (e.g. `uahp status | head`).
        # Redirect stdout to devnull so the interpreter's exit flush
        # does not raise a second BrokenPipeError, and exit cleanly.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
