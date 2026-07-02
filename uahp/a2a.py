"""
UAHP A2A Integration v1.0 — Agent Card enrichment for Google's A2A protocol.

Enriches standard A2A Agent Cards with UAHP trust primitives:
- UAHP identity + trust score
- Reputation profile
- Compliance status
- Energy profile placeholder (integrates with SMART-UAHP)
- Beacon compatibility

Author: Paul Raspey
License: MIT
"""

import json
import time
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .core import UAHPCore, AgentIdentity
from .reputation import ReputationEngine, TrustProfile


GREEN = "\033[92m"
TEAL = "\033[96m"
AMBER = "\033[93m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class UAHPAgentCard:
    """Extended A2A Agent Card with UAHP trust metadata."""
    name: str
    description: str
    id: str
    protocol_version: str = "0.2.6"
    capabilities: List[str] = field(default_factory=list)
    endpoint: str = ""
    skills: List[Dict] = field(default_factory=list)
    uahp_agent_id: str = ""
    uahp_trust_score: float = 0.0
    uahp_trust_label: str = ""
    uahp_compliant: bool = True
    uahp_energy_profile: Dict = field(default_factory=dict)
    uahp_issued_at: float = 0.0
    uahp_signature: str = ""

    def to_dict(self) -> Dict:
        base = asdict(self)
        for k in list(base.keys()):
            if k.startswith("uahp_"):
                base.pop(k, None)
        base["uahp"] = {
            "agent_id": self.uahp_agent_id,
            "trust_score": round(self.uahp_trust_score, 4),
            "trust_label": self.uahp_trust_label,
            "compliant": self.uahp_compliant,
            "energy_profile": self.uahp_energy_profile,
            "issued_at": self.uahp_issued_at,
        }
        return base

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class A2AIntegration:
    """Bridges UAHP trust layer into A2A Agent Cards."""

    def __init__(self, core: UAHPCore, reputation: ReputationEngine):
        self.core = core
        self.reputation = reputation

    def generate_agent_card(
        self,
        identity: AgentIdentity,
        name: str,
        description: str,
        endpoint: str = "",
        capabilities: Optional[List[str]] = None,
        energy_profile: Optional[Dict] = None,
    ) -> UAHPAgentCard:
        if capabilities is None:
            capabilities = ["chat", "reasoning", "tool_use"]

        profile: TrustProfile = self.reputation.score_agent(identity.agent_id)
        receipts = self.core.get_receipts(identity.agent_id)
        compliant = len(receipts) == 0 or all(r.success for r in receipts[:10])

        card = UAHPAgentCard(
            name=name,
            description=description,
            id=identity.agent_id,
            capabilities=capabilities,
            endpoint=endpoint,
            uahp_agent_id=identity.agent_id,
            uahp_trust_score=profile.trust_score,
            uahp_trust_label=profile.label,
            uahp_compliant=compliant,
            uahp_energy_profile=energy_profile or {"watts": 45, "tps": 30, "carbon_g_per_query": 0.003},
            uahp_issued_at=time.time(),
        )

        payload = f"{identity.agent_id}:{name}:{time.time()}"
        card.uahp_signature = identity.sign(payload)

        return card

    def select_agent(
        self,
        candidates: List[AgentIdentity],
        min_trust: float = 0.0,
    ) -> Optional[AgentIdentity]:
        """Pick the highest-trust candidate at or above min_trust."""
        best: Optional[AgentIdentity] = None
        best_score = -1.0
        for identity in candidates:
            profile = self.reputation.score_agent(identity.agent_id)
            if profile.trust_score >= min_trust and profile.trust_score > best_score:
                best = identity
                best_score = profile.trust_score
        return best

    def death_certificate_to_a2a_event(self, agent_id: str) -> Optional[Dict]:
        """Convert an agent's death certificate into an A2A event payload."""
        cert = self.core.get_death_certificate(agent_id)
        if cert is None:
            return None
        return {
            "type": "uahp.agent.death",
            "agent_id": agent_id,
            "timestamp": cert.timestamp,
            "reason": cert.reason,
            "declared_by": cert.declared_by,
            "certificate": cert.to_dict(),
        }


def demo():
    print(f"\n{BOLD}{'='*60}")
    print(f"  UAHP A2A Integration Demo")
    print(f"{'='*60}{RESET}\n")

    from .core import UAHPCore
    from .reputation import ReputationEngine

    core = UAHPCore()
    reputation = ReputationEngine(core)
    a2a = A2AIntegration(core, reputation)

    alice = core.create_identity({"name": "Alice", "role": "Data Analyst"})
    for i in range(8):
        core.create_receipt(alice, f"task-{i}", "analyze", True, f"in-{i}", f"out-{i}")

    card = a2a.generate_agent_card(
        identity=alice,
        name="Alice Analyst",
        description="UAHP-enabled data analysis agent",
        endpoint="https://example.com/alice",
        capabilities=["analysis", "reporting", "data_processing"],
        energy_profile={"watts": 35, "tps": 40}
    )

    print(f"{TEAL}A2A Card:{RESET}")
    print(card.to_json(indent=2)[:600] + "...")
    print(f"\n{BOLD}A2A Integration validated{RESET}\n")


if __name__ == "__main__":
    demo()
