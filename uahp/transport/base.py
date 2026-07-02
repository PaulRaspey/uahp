"""
UAHP Transport Base — v0.7.1
Aggressively simple. Just bytes.

The transport layer has exactly one job:
move bytes from one agent to another.

It does not know about envelopes.
It does not know about signing policies.
It does not know about session caches.
It does not know about delivery guarantees.
It does not know about fragmentation.

All of that lives above this layer.
The SessionCache and TieredSigner never touch the transport.
The transport never touches the SessionCache or TieredSigner.

The contract is four methods:

    connect()           — establish the connection
    send(payload)       — push bytes down the wire
    receive()           — pull bytes off the wire
    close()             — clean shutdown

That is the entire interface.

Async strategy: pure asyncio coroutines.
gRPC, MQTT, and HTTP all have native async implementations.
asyncio is the correct foundation for non-blocking I/O across all three.

For constrained devices that cannot run asyncio (embedded systems,
LoRaWAN sensors, drone flight controllers), a SyncTransportAdapter
wraps any UAHPTransport and provides a blocking interface.
The constrained device uses the shim. Everything else uses async directly.
"""

from __future__ import annotations
import asyncio
from abc import ABC, abstractmethod
from typing import Optional


class UAHPTransport(ABC):
    """
    Abstract base for all UAHP transport implementations.
    Implement four methods. That is all.
    The protocol layer handles everything else.
    """

    @abstractmethod
    async def connect(self) -> bool:
        """
        Establish the transport connection.
        Returns True if connected, False on failure.
        Idempotent - safe to call if already connected.
        """
        ...

    @abstractmethod
    async def send(self, payload: bytes) -> bool:
        """
        Send raw bytes to the connected peer.
        Returns True if the bytes left this process.
        Does not guarantee delivery - that is the protocol layer's job.
        """
        ...

    @abstractmethod
    async def receive(self) -> bytes:
        """
        Receive raw bytes from the connected peer.
        Blocks (non-blocking in asyncio sense) until data arrives.
        Raises TransportClosedError if the connection has closed.
        """
        ...

    @abstractmethod
    async def close(self) -> None:
        """
        Clean shutdown of the transport connection.
        Safe to call multiple times.
        """
        ...

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """True if the transport has an active connection."""
        ...


class TransportClosedError(Exception):
    """Raised by receive() when the transport connection has closed."""
    pass


class TransportConnectionError(Exception):
    """Raised by connect() or send() when the connection fails."""
    pass


class SyncTransportAdapter:
    """
    Synchronous wrapper for constrained devices.

    Wraps any UAHPTransport and provides blocking method calls.
    Use this on embedded systems, LoRaWAN sensors, drone controllers,
    or any environment that cannot run an asyncio event loop.

    The protocol layer above never changes.
    The constrained device just uses this shim instead of await.
    """

    def __init__(self, transport: UAHPTransport):
        self._transport = transport
        self._loop = asyncio.new_event_loop()

    def connect(self) -> bool:
        return self._loop.run_until_complete(self._transport.connect())

    def send(self, payload: bytes) -> bool:
        return self._loop.run_until_complete(self._transport.send(payload))

    def receive(self) -> bytes:
        return self._loop.run_until_complete(self._transport.receive())

    def close(self) -> None:
        self._loop.run_until_complete(self._transport.close())

    @property
    def is_connected(self) -> bool:
        return self._transport.is_connected

    def __del__(self):
        if not self._loop.is_closed():
            self._loop.close()


class InMemoryTransport(UAHPTransport):
    """
    In-memory transport for testing and local multi-agent scenarios.
    No network. No dependencies. Just two asyncio queues.

    Usage:
        a_to_b = asyncio.Queue()
        b_to_a = asyncio.Queue()

        alice = InMemoryTransport(send_queue=a_to_b, recv_queue=b_to_a)
        bob   = InMemoryTransport(send_queue=b_to_a, recv_queue=a_to_b)

        await alice.connect()
        await alice.send(b"hello")
        data = await bob.receive()  # b"hello"
    """

    def __init__(
        self,
        send_queue: Optional[asyncio.Queue] = None,
        recv_queue: Optional[asyncio.Queue] = None,
    ):
        self._send_queue = send_queue or asyncio.Queue()
        self._recv_queue = recv_queue or asyncio.Queue()
        self._connected = False

    async def connect(self) -> bool:
        self._connected = True
        return True

    async def send(self, payload: bytes) -> bool:
        if not self._connected:
            return False
        await self._send_queue.put(payload)
        return True

    async def receive(self) -> bytes:
        if not self._connected:
            raise TransportClosedError("Transport is not connected")
        return await self._recv_queue.get()

    async def close(self) -> None:
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected
