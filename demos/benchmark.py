"""
UAHP micro-benchmark: full mutual handshakes per second and encrypted
signed receipts per second, in-process, single core.

    python3 demos/benchmark.py

Measures the whole protocol path, not primitives: a handshake is all
three messages plus completion (four Ed25519 signatures verified, two
X25519 exchanges, HKDF); a receipt is create + seal into an AEAD frame
+ open + signature verify on the receiving side.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore, Receipt


def bench_handshakes(seconds: float = 2.0) -> float:
    core = UAHPCore()
    a = core.create_identity({"name": "bench-a"})
    b = core.create_identity({"name": "bench-b"})
    count, start = 0, time.perf_counter()
    while time.perf_counter() - start < seconds:
        m1 = core.handshake_init(a, b.to_public())
        m2 = core.handshake_respond(b, m1)
        m3 = core.handshake_finalize(a, m2)
        result = core.handshake_complete(b, m3)
        assert result.success
        count += 1
    return count / (time.perf_counter() - start)


def bench_receipts(seconds: float = 2.0) -> float:
    core = UAHPCore()
    a = core.create_identity({"name": "bench-a"})
    b = core.create_identity({"name": "bench-b"})
    m1 = core.handshake_init(a, b.to_public())
    m2 = core.handshake_respond(b, m1)
    m3 = core.handshake_finalize(a, m2)
    result = core.handshake_complete(b, m3)
    session = core.get_session(result.session_token)
    sender = session.record_channel(a.agent_id)
    receiver = session.record_channel(b.agent_id)

    count, start = 0, time.perf_counter()
    while time.perf_counter() - start < seconds:
        receipt = core.create_receipt(
            a, f"bench-{count}", "benchmark", True,
            input_data="in", output_data="out")
        frame = sender.seal({"receipt": receipt.to_dict(),
                             "public_key": a.public_key})
        inner = receiver.open_json(frame)
        assert core.verify_receipt(Receipt(**inner["receipt"]),
                                   inner["public_key"])
        count += 1
    return count / (time.perf_counter() - start)


def main() -> int:
    hs = bench_handshakes()
    rc = bench_receipts()
    print(f"handshakes/sec (full 3-message mutual, in-process): {hs:,.0f}")
    print(f"encrypted signed receipts/sec (create+seal+open+verify): {rc:,.0f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
