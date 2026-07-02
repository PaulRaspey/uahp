"""
UAHP Reputation Engine v1.0 — Adaptive trust scoring with decay.

Weights from UAHP-Stack README:
    delivery_rate:  0.40 (task success ratio)
    consistency:    0.30 (variance in performance)
    recency:        0.20 (time since last activity)
    volume:         0.10 (total interactions)

Trust decays when agents go silent. Receipts are the evidence.

Author: Paul Raspey
License: MIT
"""

import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .core import UAHPCore, Receipt


AMBER = "\033[93m"
GREEN = "\033[92m"
TEAL = "\033[96m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class TrustProfile:
    """Complete trust assessment for an agent."""
    agent_id: str
    trust_score: float
    label: str
    delivery_rate: float
    consistency: float
    recency_score: float
    volume_score: float
    total_receipts: int
    chain_valid: bool
    is_alive: bool
    assessed_at: float


class ReputationEngine:
    """
    Computes trust scores from UAHP receipt history.

    The score is a weighted composite of four factors, with decay
    applied when agents go inactive. Dead agents get score 0.

    Usage:
        core = UAHPCore()
        reputation = ReputationEngine(core)

        identity = core.create_identity({"name": "worker"})
        # ... agent does work, creates receipts ...

        profile = reputation.score_agent(identity.agent_id)
        print(f"Trust: {profile.trust_score:.2f} ({profile.label})")
    """

    # Weight configuration (matches README)
    W_DELIVERY = 0.40
    W_CONSISTENCY = 0.30
    W_RECENCY = 0.20
    W_VOLUME = 0.10

    # Decay parameters
    DECAY_START_DAYS = 7      # Start decaying after 7 days inactive
    DECAY_HALFLIFE_DAYS = 30  # Half-life of 30 days

    # Volume normalization
    VOLUME_FULL_AT = 50  # 50 receipts = full volume score

    def __init__(self, core: UAHPCore):
        self.core = core

    @staticmethod
    def trust_label(score: float) -> str:
        if score >= 0.85:
            return "EXCELLENT"
        if score >= 0.70:
            return "GOOD"
        if score >= 0.50:
            return "NEUTRAL"
        if score >= 0.30:
            return "CAUTION"
        return "UNTRUSTED"

    def score_agent(self, agent_id: str) -> TrustProfile:
        """Compute full trust profile for an agent."""
        inputs = self.core.get_trust_inputs(agent_id)

        # Dead agents score 0
        if not inputs["is_alive"]:
            return TrustProfile(
                agent_id=agent_id,
                trust_score=0.0,
                label="DEAD",
                delivery_rate=0.0,
                consistency=0.0,
                recency_score=0.0,
                volume_score=0.0,
                total_receipts=inputs["total_tasks"],
                chain_valid=inputs["chain_valid"],
                is_alive=False,
                assessed_at=time.time(),
            )

        # No receipts = neutral baseline
        if inputs["total_tasks"] == 0:
            return TrustProfile(
                agent_id=agent_id,
                trust_score=0.50,
                label="NEUTRAL",
                delivery_rate=0.0,
                consistency=1.0,
                recency_score=1.0,
                volume_score=0.0,
                total_receipts=0,
                chain_valid=True,
                is_alive=True,
                assessed_at=time.time(),
            )

        # 1. Delivery rate (0.0 - 1.0)
        delivery = inputs["delivery_rate"]

        # 2. Consistency (low variance in success = high consistency)
        receipts = self.core.get_receipts(agent_id)
        consistency = self._compute_consistency(receipts)

        # 3. Recency (decays with inactivity)
        recency = self._compute_recency(inputs["latest_timestamp"])

        # 4. Volume (more interactions = more data = more trust)
        volume = min(1.0, inputs["total_tasks"] / self.VOLUME_FULL_AT)

        # Weighted composite
        raw_score = (
            self.W_DELIVERY * delivery
            + self.W_CONSISTENCY * consistency
            + self.W_RECENCY * recency
            + self.W_VOLUME * volume
        )

        # Chain integrity penalty
        if not inputs["chain_valid"]:
            raw_score *= 0.5  # Severe penalty for tampered chains

        # Clamp to [0, 1]
        score = max(0.0, min(1.0, raw_score))

        return TrustProfile(
            agent_id=agent_id,
            trust_score=round(score, 4),
            label=self.trust_label(score),
            delivery_rate=round(delivery, 4),
            consistency=round(consistency, 4),
            recency_score=round(recency, 4),
            volume_score=round(volume, 4),
            total_receipts=inputs["total_tasks"],
            chain_valid=inputs["chain_valid"],
            is_alive=True,
            assessed_at=time.time(),
        )

    def _compute_consistency(self, receipts: List[Receipt]) -> float:
        """
        Measure consistency using rolling window variance.
        An agent that sometimes succeeds and sometimes fails is inconsistent.
        """
        if len(receipts) < 2:
            return 1.0

        # Sliding window of 10
        window_size = min(10, len(receipts))
        recent = receipts[-window_size:]
        results = [1.0 if r.success else 0.0 for r in recent]

        mean = sum(results) / len(results)
        variance = sum((x - mean) ** 2 for x in results) / len(results)

        # Low variance = high consistency (max variance for binary is
        # 0.25, a 50/50 split). Scaled by the window success rate so an
        # agent that fails like clockwork is not rewarded for being
        # reliably bad.
        return (1.0 - (variance / 0.25)) * mean

    def _compute_recency(self, latest_timestamp: float) -> float:
        """
        Exponential decay based on time since last activity.
        Returns 1.0 if active within DECAY_START_DAYS,
        then decays with DECAY_HALFLIFE_DAYS half-life.
        """
        if latest_timestamp == 0:
            return 0.5

        age_seconds = time.time() - latest_timestamp
        age_days = age_seconds / 86400

        if age_days <= self.DECAY_START_DAYS:
            return 1.0

        excess_days = age_days - self.DECAY_START_DAYS
        decay = math.exp(-0.693 * excess_days / self.DECAY_HALFLIFE_DAYS)
        return max(0.0, decay)

    def compare_agents(self, agent_id_a: str, agent_id_b: str) -> Dict:
        """Compare trust profiles of two agents."""
        profile_a = self.score_agent(agent_id_a)
        profile_b = self.score_agent(agent_id_b)
        return {
            "agent_a": {"agent_id": agent_id_a[:12], "score": profile_a.trust_score, "label": profile_a.label},
            "agent_b": {"agent_id": agent_id_b[:12], "score": profile_b.trust_score, "label": profile_b.label},
            "preferred": agent_id_a if profile_a.trust_score >= profile_b.trust_score else agent_id_b,
        }


# ── Demo ─────────────────────────────────────────────────────────────────────

def demo():
    print(f"\n{BOLD}{'='*60}")
    print(f"  UAHP Reputation Engine v1.0 Demo")
    print(f"{'='*60}{RESET}\n")

    core = UAHPCore()
    reputation = ReputationEngine(core)

    # Create agents with different track records
    reliable = core.create_identity({"name": "Reliable Worker"})
    flaky = core.create_identity({"name": "Flaky Worker"})
    newbie = core.create_identity({"name": "New Agent"})

    print(f"{GREEN}[1] Created 3 agents{RESET}")

    # Reliable: 20 tasks, all succeed
    for i in range(20):
        core.create_receipt(reliable, f"r-{i}", "work", True, f"in-{i}", f"out-{i}")

    # Flaky: 15 tasks, 60% success
    for i in range(15):
        core.create_receipt(flaky, f"f-{i}", "work", i % 5 != 0, f"in-{i}", f"out-{i}")

    # Newbie: no tasks yet

    print(f"\n{AMBER}[2] Scoring agents:{RESET}")
    for name, aid in [("Reliable", reliable.agent_id), ("Flaky", flaky.agent_id), ("Newbie", newbie.agent_id)]:
        profile = reputation.score_agent(aid)
        color = GREEN if profile.trust_score >= 0.7 else AMBER if profile.trust_score >= 0.5 else RED
        print(f"  {name:12s}: {color}{profile.trust_score:.2f} ({profile.label}){RESET}")
        print(f"    {DIM}delivery={profile.delivery_rate:.2f} consistency={profile.consistency:.2f} "
              f"recency={profile.recency_score:.2f} volume={profile.volume_score:.2f}{RESET}")

    # Kill an agent
    core.declare_death(flaky.agent_id, "repeated_failures")
    dead_profile = reputation.score_agent(flaky.agent_id)
    print(f"\n{RED}[3] Flaky after death: {dead_profile.trust_score:.2f} ({dead_profile.label}){RESET}")

    # Compare
    print(f"\n{TEAL}[4] Comparison:{RESET}")
    comp = reputation.compare_agents(reliable.agent_id, newbie.agent_id)
    print(f"  Reliable vs Newbie: preferred = {comp['preferred'][:12]}...")

    print(f"\n{BOLD}Reputation Engine v1.0 validated{RESET}\n")


if __name__ == "__main__":
    demo()
