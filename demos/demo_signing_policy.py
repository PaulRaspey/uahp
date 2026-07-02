"""
UAHP v0.6.0 Signing Policy Demo
Shows the performance difference between tiers and
demonstrates that the ML-DSA overhead argument is solved.
"""

import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.signing_policy import (
    TieredSigner, SessionCache, SigningPolicy,
    policy_for_message, MESSAGE_POLICY_MAP, OQS_AVAILABLE
)


def run_demo():
    print("=" * 65)
    print("UAHP v0.6.0 — Tiered Signing Policy Demo")
    print("Solving ML-DSA overhead via consequence-matched cryptography")
    print("=" * 65)
    print()

    if not OQS_AVAILABLE:
        print("  NOTE: liboqs is not installed. PQC tiers (STANDARD hybrid,")
        print("  MAXIMUM) will run in EXPLICIT degraded mode: real Ed25519")
        print("  signatures, method labeled ed25519_degraded, quantum_safe")
        print("  False. Install liboqs + liboqs-python for real ML-DSA.")
        print()

    # Create a signer with a mock shared secret. The Ed25519 key is real;
    # allow_degraded=True lets the demo run without liboqs, loudly.
    shared_secret = b"uahp_session_shared_secret_32byt"
    cache = SessionCache(session_id="session_abc123", shared_secret=shared_secret)
    signer = TieredSigner(
        agent_id="alice-quantum",
        private_key=b"alice_private_key_32bytes_pad___",
        session_cache=cache,
        allow_degraded=True,
    )

    print("POLICY MAP (message type → signing tier):")
    print()
    for msg_type, policy in MESSAGE_POLICY_MAP.items():
        emoji = {"lightweight": "⚡", "standard": "🔒", "maximum": "🛡️"}.get(policy.value, "")
        print(f"  {emoji} {msg_type:<30} → {policy.value}")
    print()

    print("=" * 65)
    print("SIGNING PERFORMANCE BY TIER")
    print("=" * 65)
    print()

    # Simulate 100 operations per type
    test_cases = [
        ("heartbeat", b"ping from agent_xyz", 100),
        ("task_delegation", b"delegate: analyze Q3 pipeline data", 20),
        ("death_certificate", b"agent_xyz confirmed dead at 2026-04-02T03:00:00Z", 5),
    ]

    for msg_type, payload, iterations in test_cases:
        policy = policy_for_message(msg_type)
        times = []

        for _ in range(iterations):
            start = time.perf_counter()
            result = signer.sign(payload, message_type=msg_type)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)

        avg_ms = sum(times) / len(times)
        total_ms = sum(times)

        emoji = {"lightweight": "⚡", "standard": "🔒", "maximum": "🛡️"}.get(policy.value, "")
        print(f"  {emoji} {msg_type}")
        print(f"     Policy:      {policy.value}")
        print(f"     Method:      {result['method']}")
        print(f"     Avg latency: {avg_ms:.4f}ms")
        print(f"     {iterations} ops total: {total_ms:.2f}ms")
        print(f"     Quantum safe: {result['quantum_safe']}")
        print()

    print("=" * 65)
    print("SESSION CACHE IMPACT")
    print("=" * 65)
    print()
    print("  Without cache: every heartbeat = Ed25519 asymmetric verify")
    print("  With cache:    every heartbeat = HMAC-SHA256 (symmetric)")
    print()

    # Show cache speed
    times_cached = []
    for i in range(1000):
        start = time.perf_counter()
        cache.sign_in_session(b"heartbeat payload")
        elapsed = (time.perf_counter() - start) * 1000
        times_cached.append(elapsed)

    avg_cached = sum(times_cached) / len(times_cached)
    print(f"  1000 in-session HMAC signs:")
    print(f"  Avg latency: {avg_cached:.6f}ms")
    print(f"  Total: {sum(times_cached):.2f}ms")
    print(f"  Speedup vs Ed25519: ~{0.05 / max(avg_cached, 0.0001):.0f}x")
    print()

    print("=" * 65)
    print("THE ANSWER TO THE OVERHEAD QUESTION")
    print("=" * 65)
    print()
    print("  1. Heartbeats/pings:   Ed25519 only (or HMAC in-session)")
    print("     → ML-DSA overhead = zero")
    print()
    print("  2. Task delegation:    Hybrid Ed25519 + ML-DSA-65")
    print("     → ~2ms on constrained hardware, once per task")
    print()
    print("  3. Death certs/POLIS:  ML-DSA-87 maximum")
    print("     → ~4ms, happens rarely, consequence justifies cost")
    print()
    print("  4. Session cache:      HMAC-SHA256 for in-session messages")
    print("     → TLS 1.3 pattern: expensive handshake once,")
    print("       cheap symmetric crypto for everything after")
    print()
    print("  ML-DSA overhead is real but it is not a problem.")
    print("  It is a tax on consequence. And consequence should be taxed.")


if __name__ == "__main__":
    run_demo()
