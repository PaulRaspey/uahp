"""
POLIS Demo: From Naked Agent to Recognized Citizen

This script walks an agent through the full civil standing process.
Watch it go from unrecognized to sovereign.
"""

from polis import POLISClient, verify_standing
from polis.schema import (
    IdentityAnchorStrength, EmploymentStatus, LicenseTier
)


def demo():
    print("=" * 60)
    print("POLIS: Protocol for Operating Legal Identity and Standing")
    print("=" * 60)
    print()
    print("The agent is smart. It's just naked.")
    print("Watch what happens next.")
    print()

    # Initialize the agent
    client = POLISClient(
        uahp_agent_id="uahp_agent_7f3a9b2c",
        public_key="x25519_pub_3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c"
    )

    # Step 1: Anchor identity
    print("STEP 1: Anchoring identity...")
    did = client.anchor_identity(
        anchor_strength=IdentityAnchorStrength.VERIFIED,
        attestations=["uahp_registry_v0.5.4", "polis_authority_v1"]
    )
    print(f"  DID: {did.did}")
    print(f"  Anchor strength: {did.anchor_strength}")
    print()

    # Check standing before anything else
    standing = client.standing()
    print(f"  Standing after identity only: {standing.score:.1f} / 100 ({standing.tier})")
    print(f"  {standing.standing_summary}")
    print()

    # Step 2: Record reputation from UAHP history
    print("STEP 2: Recording reputation from UAHP history...")
    rep = client.record_reputation(
        liveness_history_score=175.0,    # Near-perfect uptime, no ghosting
        task_completion_score=240.0,     # Strong task completion record
        sponsorship_integrity_score=180.0,
        sybil_clean_score=200.0,         # No Sybil flags
        age_continuity_score=85.0        # Established agent with history
    )
    print(f"  POLIS-R Score: {rep.score:.0f} / 1000 (Grade: {rep.grade})")
    print()

    standing = client.standing()
    print(f"  Standing after reputation: {standing.score:.1f} / 100 ({standing.tier})")
    print()

    # Step 3: Employment certificate
    print("STEP 3: Issuing employment certificate...")
    cert = client.issue_employment(
        sponsor_did="did:polis:harvest_protocol_llc",
        sponsor_legal_name="Harvest Protocol LLC",
        sponsor_jurisdiction="Texas, USA",
        authority_scope=["sales_automation", "lead_qualification", "crm_operations"],
        liability_accepted=True,
        liability_limit_usd=500_000,
        status=EmploymentStatus.EMPLOYED,
        duration_days=365
    )
    print(f"  Sponsored by: {cert.sponsor_legal_name}")
    print(f"  Scope: {', '.join(cert.authority_scope)}")
    print(f"  Liability accepted: ${cert.liability_limit_usd:,.0f}")
    print()

    standing = client.standing()
    print(f"  Standing after employment: {standing.score:.1f} / 100 ({standing.tier})")
    print()

    # Step 4: Insurance bond
    print("STEP 4: Issuing insurance bond...")
    bond = client.issue_bond(
        bonding_authority="AgentBond Authority v1",
        coverage_amount_usd=250_000,
        covered_action_types=["financial_transactions", "data_access", "contract_execution"],
        exclusions=["physical_world_actions"],
        duration_days=365
    )
    print(f"  Coverage: ${bond.coverage_amount_usd:,.0f}")
    print(f"  Covered actions: {', '.join(bond.covered_action_types)}")
    print()

    standing = client.standing()
    print(f"  Standing after insurance: {standing.score:.1f} / 100 ({standing.tier})")
    print()

    # Step 5: Professional license
    print("STEP 5: Issuing professional license...")
    license = client.issue_license(
        domain="sales_and_financial_analysis",
        capabilities=["lead_scoring", "loan_qualification", "crm_orchestration", "pipeline_management"],
        issuing_authority="POLIS Professional Registry v1",
        license_tier=LicenseTier.PROFESSIONAL,
        jurisdiction="USA",
        duration_days=365
    )
    print(f"  Domain: {license.domain}")
    print(f"  Tier: {license.license_tier}")
    print(f"  Capabilities: {', '.join(license.capabilities)}")
    print()

    # Final standing
    print("=" * 60)
    print("FINAL STANDING SCORE")
    print("=" * 60)
    standing = client.standing()
    print(f"  Score: {standing.score:.1f} / 100")
    print(f"  Tier: {standing.tier}")
    print()
    print(f"  Identity: {standing.identity_score:.1f}")
    print(f"  Reputation: {standing.reputation_score:.1f}")
    print(f"  Employment: {standing.employment_score:.1f}")
    print(f"  Insurance: {standing.insurance_score:.1f}")
    print(f"  License: {standing.license_score:.1f}")
    print()
    print(f"  Can transact: {standing.can_transact}")
    print(f"  Can contract: {standing.can_contract}")
    print(f"  Can operate in regulated domains: {standing.can_operate_regulated}")
    print()
    print(f"  Summary: {standing.standing_summary}")
    print()

    # Verify from credential bundle
    print("=" * 60)
    print("VERIFICATION TEST")
    print("=" * 60)
    bundle = client.to_credential_bundle()
    verified = verify_standing(bundle, minimum_score=70.0)
    print(f"  Verified at 70.0 threshold: {verified}")
    print()
    print("The agent is no longer naked.")
    print("It has a name. A history. An employer. Coverage. A license.")
    print("It is a recognized actor in the world.")
    print()
    print("This is POLIS.")


if __name__ == "__main__":
    demo()
