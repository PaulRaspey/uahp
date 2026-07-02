"""
UAHP Extended Tests
====================
Covers edge cases, the get_receipts limit parameter, reputation scoring,
and the MCP tool interface.

Run: python3 tests/test_extended.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore, AgentIdentity
from uahp.reputation import ReputationEngine, TrustProfile
from uahp.mcp_server import handle_request


def test_get_receipts_limit():
    """Test that get_receipts respects the limit parameter."""
    print("[1] get_receipts limit parameter...")

    uahp = UAHPCore()
    agent = uahp.create_identity({"name": "Limiter"})

    # Create 10 receipts
    for i in range(10):
        uahp.create_receipt(
            identity=agent,
            task_id=f"task-{i:03d}",
            action="test_action",
            success=True,
            input_data=f"input-{i}",
            output_data=f"output-{i}",
            duration_ms=100 + i * 10,
        )

    # No limit: all 10
    all_receipts = uahp.get_receipts(agent.agent_id)
    assert len(all_receipts) == 10, f"Expected 10, got {len(all_receipts)}"

    # Limit 3: last 3 receipts
    limited = uahp.get_receipts(agent.agent_id, limit=3)
    assert len(limited) == 3, f"Expected 3, got {len(limited)}"
    assert limited[0].task_id == "task-007", f"Expected task-007, got {limited[0].task_id}"
    assert limited[-1].task_id == "task-009", f"Expected task-009, got {limited[-1].task_id}"

    # Limit 1: only the last receipt
    single = uahp.get_receipts(agent.agent_id, limit=1)
    assert len(single) == 1
    assert single[0].task_id == "task-009"

    # Limit larger than total: returns all
    over = uahp.get_receipts(agent.agent_id, limit=100)
    assert len(over) == 10

    # Limit 0 or None: returns all
    zero = uahp.get_receipts(agent.agent_id, limit=0)
    assert len(zero) == 10
    none = uahp.get_receipts(agent.agent_id, limit=None)
    assert len(none) == 10

    print("  PASSED")


def test_get_receipts_mcp_tool():
    """Test uahp_get_receipts via MCP tool interface."""
    print("[2] uahp_get_receipts MCP tool...")

    # Create identity via MCP
    resp = handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "uahp_create_identity",
            "arguments": {"name": "MCP-Limiter"},
        },
    })
    agent_id = json.loads(resp["result"]["content"][0]["text"])["agent_id"]

    # Create 5 receipts via MCP
    for i in range(5):
        handle_request({
            "jsonrpc": "2.0", "id": 10 + i, "method": "tools/call",
            "params": {
                "name": "uahp_create_receipt",
                "arguments": {
                    "agent_id": agent_id,
                    "task_id": f"mcp-task-{i}",
                    "action": "mcp_test",
                    "duration_ms": 200,
                    "success": True,
                },
            },
        })

    # Get all receipts
    resp = handle_request({
        "jsonrpc": "2.0", "id": 20, "method": "tools/call",
        "params": {
            "name": "uahp_get_receipts",
            "arguments": {"agent_id": agent_id},
        },
    })
    result = json.loads(resp["result"]["content"][0]["text"])
    assert result["total"] == 5, f"Expected 5, got {result['total']}"

    # Get limited receipts
    resp = handle_request({
        "jsonrpc": "2.0", "id": 21, "method": "tools/call",
        "params": {
            "name": "uahp_get_receipts",
            "arguments": {"agent_id": agent_id, "limit": 2},
        },
    })
    result = json.loads(resp["result"]["content"][0]["text"])
    assert result["total"] == 2, f"Expected 2, got {result['total']}"
    assert result["receipts"][-1]["task_id"] == "mcp-task-4"

    print("  PASSED")


def test_get_receipts_in_tools_list():
    """Verify uahp_get_receipts appears in tools/list."""
    print("[3] uahp_get_receipts in tools/list...")

    resp = handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
    })
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "uahp_get_receipts" in tool_names, f"Tool not found in {tool_names}"

    print("  PASSED")


def test_reputation_zero_delivery():
    """An agent with 0% delivery should score very low."""
    print("[4] Reputation: zero delivery penalty...")

    uahp = UAHPCore()
    agent = uahp.create_identity({"name": "Failure"})

    for i in range(5):
        uahp.create_receipt(
            identity=agent,
            task_id=f"fail-{i}",
            action="fail",
            success=False,
            input_data="x",
            output_data="err",
            duration_ms=100,
        )

    rep = ReputationEngine(uahp)
    profile = rep.score_agent(agent.agent_id)
    assert profile.trust_score < 0.35, f"0% delivery should score < 0.35, got {profile.trust_score:.4f}"
    assert profile.delivery_rate == 0.0

    print(f"  Score: {profile.trust_score:.4f} - PASSED")


def test_reputation_consistency_window():
    """Erratic agents score lower on consistency than steady agents
    with the SAME overall delivery rate (sliding window of 10)."""
    print("[5] Reputation: consistency window...")

    uahp = UAHPCore()
    steady = uahp.create_identity({"name": "Steady"})
    erratic = uahp.create_identity({"name": "Erratic"})

    # Both agents: 20 receipts, 50% overall delivery rate.
    # Steady: 10 failures first, then 10 successes (recent window is uniform).
    for i in range(10):
        uahp.create_receipt(identity=steady, task_id=f"st-fail-{i}", action="run",
                            success=False, input_data="x", output_data="y")
    for i in range(10):
        uahp.create_receipt(identity=steady, task_id=f"st-ok-{i}", action="run",
                            success=True, input_data="x", output_data="y")

    # Erratic: alternating success/failure (recent window is maximally noisy).
    for i in range(20):
        uahp.create_receipt(identity=erratic, task_id=f"er-{i}", action="run",
                            success=(i % 2 == 0), input_data="x", output_data="y")

    rep = ReputationEngine(uahp)
    steady_p = rep.score_agent(steady.agent_id)
    erratic_p = rep.score_agent(erratic.agent_id)

    assert steady_p.consistency > erratic_p.consistency, (
        f"Steady consistency ({steady_p.consistency:.4f}) should beat "
        f"erratic ({erratic_p.consistency:.4f})"
    )
    assert steady_p.trust_score > erratic_p.trust_score, (
        f"Steady ({steady_p.trust_score:.4f}) should beat Erratic ({erratic_p.trust_score:.4f})"
    )

    print(f"  Steady: {steady_p.trust_score:.4f}, Erratic: {erratic_p.trust_score:.4f} - PASSED")


def test_death_certificate_blocks_trust():
    """A dead agent must fail liveness and score 0 trust."""
    print("[6] Death certificate blocks liveness and trust...")

    uahp = UAHPCore()
    agent = uahp.create_identity({"name": "Mortal"})
    assert uahp.is_alive(agent.agent_id) is True

    cert = uahp.declare_death(agent.agent_id, reason="test", declared_by="system")
    assert cert is not None
    assert cert.declared_by == "system"
    assert uahp.is_alive(agent.agent_id) is False

    rep = ReputationEngine(uahp)
    profile = rep.score_agent(agent.agent_id)
    assert profile.trust_score == 0.0
    assert profile.label == "DEAD"

    print("  PASSED")


def main():
    print()
    print("UAHP Extended Tests")
    print("=" * 60)
    print()

    test_get_receipts_limit()
    test_get_receipts_mcp_tool()
    test_get_receipts_in_tools_list()
    test_reputation_zero_delivery()
    test_reputation_consistency_window()
    test_death_certificate_blocks_trust()

    print()
    print("=" * 60)
    print("All extended tests passed.")
    print()


if __name__ == "__main__":
    main()
