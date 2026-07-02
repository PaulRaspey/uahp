"""
UAHP MCP Server — JSON-RPC 2.0 over stdio, MCP tool protocol.

Exposes all UAHP operations as MCP tools (tools/list + tools/call)
so Claude Desktop, Claude Code, or any MCP client can call them.

Author: Paul Raspey
License: MIT
"""

import sys
import json
import asyncio
from typing import Dict, Optional

from .core import UAHPCore, AgentIdentity
from .reputation import ReputationEngine
from .compliance import ComplianceEngine
from .a2a import A2AIntegration


PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "uahp", "version": "1.0.0"}


def _tool(name: str, description: str, properties: Dict, required=None) -> Dict:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
        },
    }


TOOLS = [
    _tool(
        "uahp_create_identity",
        "Create a new UAHP agent identity (Ed25519 keypair). "
        "All arguments are stored as identity metadata.",
        {"name": {"type": "string"}, "description": {"type": "string"}},
    ),
    _tool(
        "uahp_handshake",
        "Run a mutual authentication handshake between two agents.",
        {"agent_id_a": {"type": "string"}, "agent_id_b": {"type": "string"}},
        required=["agent_id_a", "agent_id_b"],
    ),
    _tool(
        "uahp_liveness_check",
        "Check whether an agent is alive (exists and is not revoked).",
        {"agent_id": {"type": "string"}},
        required=["agent_id"],
    ),
    _tool(
        "uahp_declare_death",
        "Issue an irreversible death certificate for an agent.",
        {
            "agent_id": {"type": "string"},
            "reason": {"type": "string"},
            "declared_by": {"type": "string"},
        },
        required=["agent_id"],
    ),
    _tool(
        "uahp_create_receipt",
        "Create a signed, chain-hashed completion receipt for an agent.",
        {
            "agent_id": {"type": "string"},
            "task_id": {"type": "string"},
            "action": {"type": "string"},
            "success": {"type": "boolean"},
            "duration_ms": {"type": "number"},
            "input_data": {"type": "string"},
            "output_data": {"type": "string"},
        },
        required=["agent_id"],
    ),
    _tool(
        "uahp_get_receipts",
        "Get an agent's receipts. With limit, return only the last N.",
        {"agent_id": {"type": "string"}, "limit": {"type": "integer"}},
        required=["agent_id"],
    ),
    _tool(
        "uahp_trust_score",
        "Compute an agent's trust profile from its receipt history.",
        {"agent_id": {"type": "string"}},
        required=["agent_id"],
    ),
    _tool(
        "uahp_compliance_report",
        "Generate an EU AI Act compliance report for an agent.",
        {"agent_id": {"type": "string"}},
        required=["agent_id"],
    ),
    _tool(
        "uahp_agent_card",
        "Generate a UAHP-enriched A2A Agent Card.",
        {
            "agent_id": {"type": "string"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "endpoint": {"type": "string"},
        },
        required=["agent_id"],
    ),
    _tool(
        "uahp_list_agents",
        "List all agents created through this server, with liveness.",
        {},
    ),
]


class UAHPMCPServer:
    def __init__(self):
        self.core = UAHPCore()
        self.reputation = ReputationEngine(self.core)
        self.compliance = ComplianceEngine(self.core)
        self.a2a = A2AIntegration(self.core, self.reputation)
        self.agents: Dict[str, AgentIdentity] = {}

    # ── Tool dispatch ────────────────────────────────────────────────────

    def _get_agent(self, agent_id: str) -> AgentIdentity:
        identity = self.agents.get(agent_id) or self.core.get_identity(agent_id)
        if not identity:
            raise ValueError(f"Agent not found: {agent_id}")
        return identity

    def call_tool(self, name: str, arguments: Dict) -> Dict:
        if name == "uahp_create_identity":
            identity = self.core.create_identity(dict(arguments))
            self.agents[identity.agent_id] = identity
            return {"agent_id": identity.agent_id, "public_key": identity.public_key}

        if name == "uahp_handshake":
            id_a = self._get_agent(arguments["agent_id_a"])
            id_b = self._get_agent(arguments["agent_id_b"])
            hs = self.core.handshake(id_a, id_b)
            return {"success": hs.success, "session_token": hs.session_token, "error": hs.error}

        if name == "uahp_liveness_check":
            return {"alive": self.core.is_alive(arguments["agent_id"])}

        if name == "uahp_declare_death":
            cert = self.core.declare_death(
                arguments["agent_id"],
                reason=arguments.get("reason", "silent"),
                declared_by=arguments.get("declared_by", "self"),
            )
            result = {"success": cert is not None}
            if cert:
                result["cert"] = cert.to_dict()
            return result

        if name == "uahp_create_receipt":
            identity = self._get_agent(arguments["agent_id"])
            receipt = self.core.create_receipt(
                identity=identity,
                task_id=arguments.get("task_id", ""),
                action=arguments.get("action", ""),
                success=arguments.get("success", True),
                input_data=arguments.get("input_data", ""),
                output_data=arguments.get("output_data", ""),
                duration_ms=arguments.get("duration_ms", 0.0),
            )
            return receipt.to_dict()

        if name == "uahp_get_receipts":
            receipts = self.core.get_receipts(
                arguments["agent_id"], limit=arguments.get("limit")
            )
            return {
                "total": len(receipts),
                "receipts": [r.to_dict() for r in receipts],
            }

        if name == "uahp_trust_score":
            profile = self.reputation.score_agent(arguments["agent_id"])
            return {
                "trust_score": profile.trust_score,
                "label": profile.label,
                "delivery_rate": profile.delivery_rate,
                "consistency": profile.consistency,
                "total_receipts": profile.total_receipts,
            }

        if name == "uahp_compliance_report":
            report = self.compliance.generate_report(arguments["agent_id"])
            return report.to_dict()

        if name == "uahp_agent_card":
            identity = self._get_agent(arguments["agent_id"])
            card = self.a2a.generate_agent_card(
                identity=identity,
                name=arguments.get("name", "Unnamed Agent"),
                description=arguments.get("description", ""),
                endpoint=arguments.get("endpoint", ""),
                capabilities=arguments.get("capabilities"),
            )
            return card.to_dict()

        if name == "uahp_list_agents":
            return {
                "agents": [
                    {"agent_id": aid, "alive": self.core.is_alive(aid)}
                    for aid in self.agents
                ]
            }

        raise ValueError(f"Unknown tool: {name}")

    # ── JSON-RPC / MCP routing ───────────────────────────────────────────

    def handle_request(self, request: Dict) -> Dict:
        method = request.get("method")
        params = request.get("params", {})
        req_id = request.get("id")

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": SERVER_INFO,
                }

            elif method == "tools/list":
                result = {"tools": TOOLS}

            elif method == "tools/call":
                tool_result = self.call_tool(
                    params.get("name", ""), params.get("arguments", {})
                )
                result = {
                    "content": [
                        {"type": "text", "text": json.dumps(tool_result)}
                    ]
                }

            else:
                raise ValueError(f"Unknown method: {method}")

            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}}


# Module-level server so `from uahp.mcp_server import handle_request` works
# and state persists across calls within a process.
_default_server = UAHPMCPServer()


def handle_request(request: Dict) -> Dict:
    return _default_server.handle_request(request)


async def main():
    server = UAHPMCPServer()
    print("UAHP MCP Server started (JSON-RPC 2.0 over stdio)", file=sys.stderr)

    try:
        while True:
            line = await asyncio.get_running_loop().run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            try:
                request = json.loads(line.strip())
                response = server.handle_request(request)
                print(json.dumps(response))
                sys.stdout.flush()
            except json.JSONDecodeError:
                pass
    except KeyboardInterrupt:
        print("\nUAHP MCP Server shutting down", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
