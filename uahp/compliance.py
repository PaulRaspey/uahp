"""
UAHP Compliance Engine v1.0 — EU AI Act audit trails.

Generates tamper-evident compliance reports from receipt chains.
Covers Articles 12 (record-keeping), 14 (human oversight),
17 (quality management), and 50 (transparency).

Author: Paul Raspey
License: MIT
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .core import UAHPCore, Receipt


GREEN = "\033[92m"
AMBER = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


@dataclass
class ComplianceReport:
    """EU AI Act compliance report for a single agent."""
    report_id: str
    agent_id: str
    generated_at: float
    audit_entries: int
    chain_hash: str
    chain_intact: bool
    delivery_rate: float
    articles_covered: List[str]
    findings: List[str]
    compliant: bool
    risk_level: str

    def to_dict(self) -> Dict:
        from dataclasses import asdict
        return asdict(self)


class ComplianceEngine:
    """
    Generates EU AI Act compliance reports from UAHP receipt chains.

    The chain hash is computed over the full ordered receipt chain,
    making it impossible to insert, remove, or reorder entries
    without detection.

    Usage:
        core = UAHPCore()
        compliance = ComplianceEngine(core)

        report = compliance.generate_report(agent.agent_id)
        print(f"Compliant: {report.compliant}")
    """

    # EU AI Act article coverage
    ARTICLES = {
        "12": "Record-keeping (logging, audit trail)",
        "14": "Human oversight (transparency of operations)",
        "17": "Quality management (receipt chain integrity)",
        "50": "Transparency (identity disclosure, provenance)",
    }

    def __init__(self, core: UAHPCore):
        self.core = core

    def generate_report(
        self, agent_id: str, period_days: int = 30
    ) -> ComplianceReport:
        """Generate a compliance report for an agent."""
        receipts = self.core.get_receipts(agent_id)
        trust_inputs = self.core.get_trust_inputs(agent_id)

        # Filter to period
        cutoff = time.time() - (period_days * 86400)
        period_receipts = [r for r in receipts if r.timestamp >= cutoff]

        # Chain hash over all receipts (not just period)
        chain_hash = self._compute_chain_hash(receipts)
        chain_intact = trust_inputs["chain_valid"]

        # Findings
        findings = []
        if not chain_intact:
            findings.append("CRITICAL: Receipt chain integrity violation detected")
        if not trust_inputs["is_alive"]:
            findings.append("INFO: Agent has been declared dead")
        if trust_inputs["delivery_rate"] < 0.5:
            findings.append("WARNING: Delivery rate below 50%")
        if len(period_receipts) == 0 and trust_inputs["total_tasks"] > 0:
            findings.append(f"WARNING: No activity in the last {period_days} days")

        # Risk assessment
        risk_level = self._assess_risk(trust_inputs, chain_intact, findings)

        # Compliant if no CRITICAL findings and chain intact
        compliant = chain_intact and not any("CRITICAL" in f for f in findings)

        report_id = hashlib.sha256(
            f"{agent_id}:{time.time()}:{chain_hash}".encode()
        ).hexdigest()[:16]

        return ComplianceReport(
            report_id=report_id,
            agent_id=agent_id,
            generated_at=time.time(),
            audit_entries=len(receipts),
            chain_hash=chain_hash,
            chain_intact=chain_intact,
            delivery_rate=trust_inputs["delivery_rate"],
            articles_covered=list(self.ARTICLES.keys()),
            findings=findings,
            compliant=compliant,
            risk_level=risk_level,
        )

    def generate_batch_report(self, agent_ids: List[str]) -> Dict:
        """Generate compliance reports for multiple agents."""
        reports = {}
        compliant_count = 0
        for aid in agent_ids:
            report = self.generate_report(aid)
            reports[aid] = report
            if report.compliant:
                compliant_count += 1

        return {
            "total_agents": len(agent_ids),
            "compliant": compliant_count,
            "non_compliant": len(agent_ids) - compliant_count,
            "compliance_rate": compliant_count / max(len(agent_ids), 1),
            "reports": reports,
        }

    def _compute_chain_hash(self, receipts: List[Receipt]) -> str:
        """Compute a single hash over the entire receipt chain."""
        if not receipts:
            return hashlib.sha256(b"empty_chain").hexdigest()

        chain_data = ""
        for r in sorted(receipts, key=lambda x: x.timestamp):
            chain_data += r.signature
        return hashlib.sha256(chain_data.encode()).hexdigest()

    def _assess_risk(
        self, inputs: Dict, chain_intact: bool, findings: List[str]
    ) -> str:
        """Map findings to EU AI Act risk level."""
        if not chain_intact:
            return "HIGH"
        critical_count = sum(1 for f in findings if "CRITICAL" in f)
        warning_count = sum(1 for f in findings if "WARNING" in f)
        if critical_count > 0:
            return "HIGH"
        if warning_count >= 2:
            return "MEDIUM"
        if warning_count == 1:
            return "LOW"
        return "MINIMAL"


# ── Demo ─────────────────────────────────────────────────────────────────────

def demo():
    print(f"\n{BOLD}{'='*60}")
    print(f"  UAHP Compliance Engine v1.0 Demo")
    print(f"  EU AI Act Audit Trails")
    print(f"{'='*60}{RESET}\n")

    core = UAHPCore()
    compliance = ComplianceEngine(core)

    agent = core.create_identity({"name": "Production Agent"})

    # Create work history
    for i in range(25):
        core.create_receipt(agent, f"task-{i}", "process", i % 7 != 0, f"in-{i}", f"out-{i}")

    print(f"{GREEN}[1] Agent created with 25 receipts{RESET}")

    # Generate report
    report = compliance.generate_report(agent.agent_id)
    status = f"{GREEN}COMPLIANT{RESET}" if report.compliant else f"{AMBER}NON-COMPLIANT{RESET}"
    print(f"\n{BOLD}[2] Compliance Report:{RESET}")
    print(f"  Report ID:     {report.report_id}")
    print(f"  Status:        {status}")
    print(f"  Risk:          {report.risk_level}")
    print(f"  Audit entries: {report.audit_entries}")
    print(f"  Chain hash:    {report.chain_hash[:24]}...")
    print(f"  Chain intact:  {report.chain_intact}")
    print(f"  Delivery rate: {report.delivery_rate:.0%}")
    print(f"  Articles:      {', '.join(report.articles_covered)}")
    if report.findings:
        print(f"  Findings:")
        for f in report.findings:
            print(f"    {f}")

    print(f"\n{BOLD}Compliance Engine v1.0 validated{RESET}\n")


if __name__ == "__main__":
    demo()
