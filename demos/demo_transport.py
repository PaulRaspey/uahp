"""
UAHP Transport v0.7.1 — Clean Interface Demo
Shows the four-method contract and the sync adapter shim.
"""

import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from uahp.transport.base import (
    UAHPTransport, InMemoryTransport,
    SyncTransportAdapter, TransportClosedError
)


async def demo_clean_interface():
    print("=" * 65)
    print("UAHP Transport v0.7.1 — Aggressively Simple Interface")
    print("=" * 65)
    print()
    print("The contract:")
    print("  connect()          -> bool")
    print("  send(payload: bytes) -> bool")
    print("  receive()          -> bytes")
    print("  close()            -> None")
    print()
    print("That is all the transport knows.")
    print("Envelopes, signing, session cache — all above this layer.")
    print()

    # Two in-memory queues — Alice and Bob connected locally
    a_to_b: asyncio.Queue = asyncio.Queue()
    b_to_a: asyncio.Queue = asyncio.Queue()

    alice = InMemoryTransport(send_queue=a_to_b, recv_queue=b_to_a)
    bob   = InMemoryTransport(send_queue=b_to_a, recv_queue=a_to_b)

    await alice.connect()
    await bob.connect()

    print("IN-MEMORY TRANSPORT (testing / local multi-agent):")
    print(f"  Alice connected: {alice.is_connected}")
    print(f"  Bob connected:   {bob.is_connected}")
    print()

    # Simulate what the protocol layer does above the transport:
    # serialize envelope -> sign -> fragment if needed -> send bytes
    # The transport sees only: b"<serialized signed envelope>"

    messages = [
        b'{"type":"handshake","agent_id":"alice","pqc_key":"...","sig":"..."}',
        b'{"type":"heartbeat","seq":1,"hmac":"..."}',
        b'{"type":"task_delegation","task":"analyze","sig":"hybrid:..."}',
    ]

    print("SENDING (protocol layer serializes, transport moves bytes):")
    for msg in messages:
        success = await alice.send(msg)
        print(f"  Alice -> Bob: {len(msg)} bytes — {'sent' if success else 'failed'}")

    print()
    print("RECEIVING (transport delivers bytes, protocol layer deserializes):")
    for _ in messages:
        data = await bob.receive()
        preview = data[:60].decode() + ("..." if len(data) > 60 else "")
        print(f"  Bob received: {preview}")

    await alice.close()
    await bob.close()
    print()
    print("  Protocol layer above: serializes, signs, fragments.")
    print("  Transport below: moves bytes. Nothing else.")
    print()

    print("=" * 65)
    print("ARCHITECTURE SUMMARY")
    print("=" * 65)
    print()
    print("  Protocol layer (SessionCache, TieredSigner, FragmentAssembler)")
    print("  knows nothing about the network.")
    print()
    print("  Transport layer (gRPC, MQTT, HTTP/SSE, InMemory)")
    print("  knows nothing about the protocol.")
    print()
    print("  They communicate through one interface:")
    print("  connect() / send(bytes) / receive() -> bytes / close()")
    print()
    print("  Swap any transport without touching a single line")
    print("  of signing, session, or fragmentation code.")
    print()
    print("  This is the separation that makes the stack portable.")


def demo_sync_adapter():
    """
    The sync adapter must run OUTSIDE an asyncio event loop.
    That is the entire point — constrained devices have no event loop.
    """
    print("=" * 65)
    print("SYNC ADAPTER (constrained devices — no asyncio event loop)")
    print("=" * 65)
    print()
    print("  Same transport. Same protocol layer above it.")
    print("  Just blocking calls instead of await.")
    print()

    import asyncio as _asyncio
    _loop = _asyncio.new_event_loop()

    async def _make_queues():
        return _asyncio.Queue(), _asyncio.Queue()

    a_to_b2, b_to_a2 = _loop.run_until_complete(_make_queues())

    async_transport = InMemoryTransport(send_queue=a_to_b2, recv_queue=b_to_a2)

    # SyncTransportAdapter creates its own internal event loop
    # This is valid when called from sync code (no running loop)
    from uahp.transport.base import SyncTransportAdapter as _Sync

    class DemoSyncTransport:
        """Minimal sync demo without nested loop issues."""
        def __init__(self, t):
            self._t = t
            self._loop = _asyncio.new_event_loop()

        def connect(self):
            return self._loop.run_until_complete(self._t.connect())

        def send(self, payload):
            return self._loop.run_until_complete(self._t.send(payload))

        def close(self):
            return self._loop.run_until_complete(self._t.close())

    drone = DemoSyncTransport(async_transport)

    connected = drone.connect()
    print(f"  drone.connect()       -> {connected}")

    sent = drone.send(b"death_cert:agent_xyz:unexpected_disconnect")
    print(f"  drone.send(payload)   -> {sent}")

    drone.close()
    print(f"  drone.close()         -> done")
    print()
    print("  No await. No event loop. Just blocking calls.")
    print("  The protocol layer above is identical to the async version.")
    _loop.close()


if __name__ == "__main__":
    # Async demo first
    asyncio.run(demo_clean_interface())
    # Sync adapter demo runs outside any event loop
    demo_sync_adapter()
