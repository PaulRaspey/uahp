"""
UAHP Stack Integration Test
============================
Exercises the full pipeline: identity -> handshake -> work -> receipts
-> reputation -> compliance -> A2A card generation -> death -> MCP tools.

Run: python3 tests/test_stack.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.core import UAHPCore, AgentIdentity
from uahp.reputation import ReputationEngine, TrustProfile
from uahp.compliance import ComplianceEngine
from uahp.a2a import A2AIntegration, UAHPAgentCard


def test_full_stack():
    """Integration test: full lifecycle of two agents interacting."""
    print("UAHP Stack Integration Test")
    print("=" * 60)

    # 1. Initialize core
    uahp = UAHPCore()
    reputation = ReputationEngine(uahp)
    compliance = ComplianceEngine(uahp)
    a2a = A2AIntegration(uahp, reputation)

    # 2. Create agent identities
    print("\n[1] Creating identities...")
    alice = uahp.create_identity({"name": "Alice", "description": "Data analyst agent"})
    bob = uahp.create_identity({"name": "Bob", "description": "Code review agent"})
    print(f"  Alice: {alice.agent_id}")
    print(f"  Bob:   {bob.agent_id}")

    # 3. Mutual authentication handshake
    print("\n[2] Handshake...")
    result = uahp.handshake(alice, bob)
    assert result.success, "Handshake failed"
    assert len(result.shared_secret) == 32, "No real shared secret derived"
    print(f"  Success: {result.success}")
    print(f"  Session: {result.session_token[:16]}...")

    # 4. Liveness checks
    print("\n[3] Liveness checks...")
    assert uahp.is_alive(alice.agent_id), "Alice liveness failed"
    assert uahp.is_alive(bob.agent_id), "Bob liveness failed"
    print(f"  Alice alive: {uahp.is_alive(alice.agent_id)}")
    print(f"  Bob alive:   {uahp.is_alive(bob.agent_id)}")

    # 5. Generate completion receipts (simulate work)
    print("\n[4] Simulating work (generating receipts)...")
    tasks = [
        ("task-001", "analyze_dataset", 1200, True),
        ("task-002", "generate_report", 3400, True),
        ("task-003", "validate_schema", 800, True),
        ("task-004", "run_pipeline", 15000, False),  # one failure
        ("task-005", "summarize_results", 2100, True),
        ("task-006", "archive_output", 450, True),
        ("task-007", "notify_stakeholders", 300, True),
    ]

    for task_id, action, dur, success in tasks:
        uahp.create_receipt(
            identity=alice,
            task_id=task_id,
            action=action,
            success=success,
            input_data=f"input for {task_id}",
            output_data=f"output for {task_id}",
            duration_ms=dur,
        )

    # Bob does fewer tasks
    for task_id, action, dur, success in tasks[:3]:
        uahp.create_receipt(
            identity=bob,
            task_id=f"bob-{task_id}",
            action=action,
            success=success,
            input_data=f"bob input for {task_id}",
            output_data=f"bob output for {task_id}",
            duration_ms=dur * 1.2,
        )

    alice_receipts = uahp.get_receipts(alice.agent_id)
    bob_receipts = uahp.get_receipts(bob.agent_id)
    assert len(alice_receipts) == 7
    assert len(bob_receipts) == 3
    assert alice_receipts[0].duration_ms == 1200
    print(f"  Alice receipts: {len(alice_receipts)}")
    print(f"  Bob receipts:   {len(bob_receipts)}")

    # 6. Reputation scoring
    print("\n[5] Trust scores...")
    alice_trust = reputation.score_agent(alice.agent_id)
    bob_trust = reputation.score_agent(bob.agent_id)
    assert 0.0 < alice_trust.trust_score <= 1.0
    assert abs(alice_trust.delivery_rate - 6 / 7) < 1e-3  # profile rounds to 4 decimals
    assert bob_trust.delivery_rate == 1.0
    print(f"  Alice: {alice_trust.trust_score:.4f} ({alice_trust.label})")
    print(f"  Bob:   {bob_trust.trust_score:.4f} ({bob_trust.label})")
    print(f"  Alice delivery rate: {alice_trust.delivery_rate:.2%}")
    print(f"  Bob delivery rate:   {bob_trust.delivery_rate:.2%}")

    # 7. Receipt verification (public-key based: anyone can verify)
    print("\n[6] Receipt verification...")
    verified = uahp.verify_receipt(alice_receipts[0], alice.public_key)
    wrong_key = uahp.verify_receipt(alice_receipts[0], bob.public_key)
    print(f"  Correct key: {verified}")
    print(f"  Wrong key:   {wrong_key}")
    assert verified, "Valid receipt failed verification"
    assert not wrong_key, "Receipt verified with the wrong public key"

    # 8. EU AI Act compliance report
    print("\n[7] Compliance report (EU AI Act)...")
    report = compliance.generate_report(alice.agent_id)
    assert report.chain_intact, "Chain should be intact"
    assert report.compliant, "Alice should be compliant"
    assert report.audit_entries == 7
    print(f"  Report ID:     {report.report_id}")
    print(f"  Risk level:    {report.risk_level}")
    print(f"  Compliant:     {report.compliant}")
    print(f"  Delivery rate: {report.delivery_rate:.2%}")
    print(f"  Chain hash:    {report.chain_hash[:24]}...")
    print(f"  Audit entries: {report.audit_entries}")
    print(f"  Articles:      {', '.join(report.articles_covered)}")

    # 9. A2A Agent Card generation
    print("\n[8] A2A Agent Card...")
    card = a2a.generate_agent_card(
        identity=alice,
        name="Alice",
        description="Data analyst agent",
        endpoint="https://agents.example.com/alice",
        capabilities=["data_analysis", "reporting"],
    )
    assert card.uahp_agent_id == alice.agent_id
    assert card.uahp_trust_score == alice_trust.trust_score
    card_dict = card.to_dict()
    assert card_dict["uahp"]["agent_id"] == alice.agent_id
    print(f"  Name:        {card.name}")
    print(f"  Trust score: {card.uahp_trust_score}")
    print(f"  Trust label: {card.uahp_trust_label}")
    print(f"  Signed:      {bool(card.uahp_signature)}")

    # 10. Agent selection (best of candidates)
    print("\n[9] Agent selection...")
    best = a2a.select_agent([alice, bob], min_trust=0.3)
    assert best is not None, "No agent selected"
    print(f"  Best agent: {best.agent_id} ({best.metadata.get('name')})")
    none_selected = a2a.select_agent([alice, bob], min_trust=1.01)
    assert none_selected is None, "min_trust above 1.0 should select nobody"

    # 11. Death certificate
    print("\n[10] Death certificate...")
    cert = uahp.declare_death(
        bob.agent_id,
        reason="Unresponsive for 48 hours",
        declared_by=alice.agent_id,
    )
    assert cert is not None
    assert cert.declared_by == alice.agent_id
    assert UAHPCore.verify_death_certificate(cert)
    assert not uahp.is_alive(bob.agent_id)
    print(f"  Bob alive:   {uahp.is_alive(bob.agent_id)}")
    print(f"  Declared by: {cert.declared_by}")
    print(f"  Reason:      {cert.reason}")

    # 12. A2A death event
    death_event = a2a.death_certificate_to_a2a_event(bob.agent_id)
    assert death_event is not None
    assert death_event["type"] == "uahp.agent.death"
    assert death_event["agent_id"] == bob.agent_id
    print(f"  A2A event type: {death_event['type']}")

    # 13. MCP server tool test
    print("\n[11] MCP server tool routing...")
    from uahp.mcp_server import handle_request

    # Test tools/list
    response = handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list"
    })
    tools = response["result"]["tools"]
    assert any(t["name"] == "uahp_create_identity" for t in tools)
    print(f"  Available tools: {len(tools)}")

    # Test create identity via MCP
    response = handle_request({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "uahp_create_identity",
            "arguments": {"name": "Charlie", "description": "Test agent"},
        },
    })
    result = json.loads(response["result"]["content"][0]["text"])
    assert "agent_id" in result and "public_key" in result
    print(f"  Created via MCP: {result['agent_id']}")

    # Test trust score via MCP
    response = handle_request({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "uahp_trust_score",
            "arguments": {"agent_id": result["agent_id"]},
        },
    })
    score_result = json.loads(response["result"]["content"][0]["text"])
    assert score_result["label"] == "NEUTRAL", "New agent should score NEUTRAL"
    print(f"  Trust (new agent): {score_result['trust_score']} ({score_result['label']})")

    print("\n" + "=" * 60)
    print("All tests passed.")


if __name__ == "__main__":
    test_full_stack()
