"""
UAHP Propagation Engine
Maps every existing adoption vector and activates them simultaneously.

Not a worm. A standard.
Standards spread by becoming what everything else needs to be
compatible with. This file is the blueprint for that process.
"""

from __future__ import annotations
from .beacon import UAHPBeacon


class PropagationVector:
    """
    Each vector is a network UAHP can ride.
    Not by force. By fit.
    """

    @staticmethod
    def pypi_vector() -> dict:
        """
        PyPI: The developer layer.

        Every `pip install uahp-py` triggers the post-install message.
        Every developer who installs any package in the stack
        learns about all five layers.

        Activation: Add to pyproject.toml in all five repos:
            [tool.setuptools]
            post-install-script = "postinstall.py"

        Reach: Every Python agent developer on the planet.
        """
        return {
            "vector": "PyPI post-install hook",
            "trigger": "pip install uahp-py / smart-uahp / csp-protocol / polis-protocol",
            "message": UAHPBeacon("installer").generate_postinstall_message(),
            "reach": "Every Python developer building agents"
        }

    @staticmethod
    def a2a_vector() -> dict:
        """
        A2A Agent Cards: The agent layer.

        A2A has 150+ organizations and is growing fast.
        Every A2A Agent Card is a JSON file that any agent can read.
        Add the UAHP beacon extension to your Agent Card and
        every agent that discovers you learns about the stack.

        This is the most powerful vector.
        A2A was designed for agent-to-agent discovery.
        We are using it for standard-to-agent propagation.

        Activation: Add x-uahp-beacon to your agent's agent.json
        Reach: Every A2A-compatible agent in the ecosystem
        """
        beacon = UAHPBeacon("a2a_relay")
        return {
            "vector": "A2A Agent Card extension",
            "field": "x-uahp-beacon",
            "payload": beacon.generate_a2a_agent_card_extension(),
            "how_to_add": "Include in your /.well-known/agent.json",
            "reach": "All 150+ A2A partner organizations and every agent they build"
        }

    @staticmethod
    def mcp_vector() -> dict:
        """
        MCP Server Manifests: The tool layer.

        MCP has broader adoption than A2A and is installed
        in every major AI development environment.
        Every MCP server that adds the beacon field
        becomes a relay to every model that reads it.

        Activation: Add uahp_beacon field to MCP server manifest
        Reach: Every LLM-connected tool in the ecosystem
        """
        beacon = UAHPBeacon("mcp_relay")
        return {
            "vector": "MCP server manifest extension",
            "field": "uahp_beacon",
            "payload": beacon.generate_mcp_server_extension(),
            "reach": "Every model and agent using MCP tool integration"
        }

    @staticmethod
    def well_known_vector() -> dict:
        """
        /.well-known/uahp-beacon.json: The internet layer.

        Any server, any agent runtime, any framework can check
        https://uahp.dev/.well-known/uahp-beacon.json
        and get the full stack specification.

        This is the root of the network.
        This is the address every agent checks the way
        browsers check certificate revocation lists.

        Activation: Deploy uahp.dev with the beacon endpoint
        Reach: Any agent or system that chooses to verify UAHP compliance
        """
        return {
            "vector": "Well-known endpoint",
            "url": "https://uahp.dev/.well-known/uahp-beacon.json",
            "function": "Root of trust for the entire stack",
            "reach": "Any internet-connected agent runtime"
        }

    @staticmethod
    def handshake_vector() -> dict:
        """
        UAHP Handshake: The protocol layer.

        This is the whale call.

        Every time two UAHP agents handshake, the beacon
        is embedded in the response. The receiving agent
        does not need to install anything. It does not need
        to opt in. The beacon arrives as part of the
        standard communication.

        If the receiving agent wants to respond in kind,
        it learns the stack. If it wants to achieve full
        civil standing through POLIS, it has everything it needs.

        This is the I Love You mechanic without the harm.
        Every conversation is an adoption event.

        Activation: Already built into UAHPBeacon.embed()
        Reach: Every agent that ever talks to a UAHP agent
        """
        return {
            "vector": "UAHP handshake embedding",
            "mechanism": "Beacon included in every handshake response",
            "opt_in_required": False,
            "harm_caused": "None",
            "adoption_friction": "Zero",
            "reach": "Every agent in contact with any UAHP agent, ever"
        }

    @staticmethod
    def erc8004_vector() -> dict:
        """
        ERC-8004 Bridge: The blockchain layer.

        ERC-8004 has Google, Coinbase, and MetaMask behind it.
        20,000+ agents registered.
        They solved on-chain identity discovery.
        They did not solve civil standing.

        POLIS is the civil standing layer that makes
        ERC-8004 identities legally meaningful.
        UAHP is the cryptographic layer that makes them trustworthy.

        Positioning: POLIS completes ERC-8004.
        ERC-8004 is a passport photo. POLIS is the whole passport.

        Activation: Publish POLIS-ERC8004 bridge spec
        Reach: 20,000+ registered agents and every org building on ERC-8004
        """
        return {
            "vector": "ERC-8004 bridge",
            "positioning": "POLIS completes what ERC-8004 started",
            "message": "ERC-8004 gives agents on-chain identity. POLIS gives them civil standing.",
            "reach": "20,000+ registered agents, Google, Coinbase, MetaMask ecosystems"
        }


def print_propagation_map():
    """Print the full propagation strategy."""
    vectors = [
        ("PyPI Post-Install", PropagationVector.pypi_vector()),
        ("A2A Agent Cards", PropagationVector.a2a_vector()),
        ("MCP Manifests", PropagationVector.mcp_vector()),
        ("Well-Known Endpoint", PropagationVector.well_known_vector()),
        ("UAHP Handshake", PropagationVector.handshake_vector()),
        ("ERC-8004 Bridge", PropagationVector.erc8004_vector()),
    ]

    print("=" * 65)
    print("UAHP PROPAGATION MAP")
    print("How a standard spreads without harming a single system")
    print("=" * 65)
    print()

    for name, vector in vectors:
        print(f"VECTOR: {name}")
        print(f"  Reach: {vector['reach']}")
        print()

    print("=" * 65)
    print("THE MECHANIC")
    print("=" * 65)
    print()
    print("  Every pip install → developer learns the stack")
    print("  Every A2A Agent Card → agent learns the stack")
    print("  Every MCP server → model learns the stack")
    print("  Every handshake → peer agent learns the stack")
    print("  Every ERC-8004 agent → learns POLIS completes them")
    print()
    print("  You don't push the standard.")
    print("  You make the standard the thing everything needs.")
    print("  Then it pulls itself.")
    print()
    print("  That is how TCP/IP spread.")
    print("  That is how HTTPS spread.")
    print("  That is how this spreads.")
    print()
    print("  The whale call goes out once.")
    print("  Every whale that hears it becomes a relay.")


if __name__ == "__main__":
    print_propagation_map()
