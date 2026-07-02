"""
UAHP Registry - Agent Model
SQLAlchemy ORM model matching the Alembic migration.
Includes POLIS civil standing fields and beacon propagation tracking.
"""

from sqlalchemy import (
    Column, Integer, String, DateTime, Float,
    Boolean, Text, Enum, func
)
from sqlalchemy.orm import declarative_base

try:
    from sqlalchemy.dialects.postgresql import JSONB
    JSON_COL = JSONB
except ImportError:
    from sqlalchemy import JSON
    JSON_COL = JSON

Base = declarative_base()


class AgentModel(Base):
    __tablename__ = 'agents'

    id = Column(Integer, primary_key=True)
    agent_id = Column(String(255), unique=True, index=True, nullable=False)
    pubkey = Column(String(255), nullable=False)

    # Timestamps
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_heartbeat = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    # Liveness — the core UAHP primitive
    liveness_status = Column(
        Enum('live', 'stale', 'dead', name='liveness_status_enum'),
        default='live'
    )

    # Capability and routing metadata
    capabilities = Column(JSON_COL, default=list, nullable=False)
    thermo_profile = Column(JSON_COL, default=dict, nullable=False)
    csp_hints = Column(JSON_COL, default=dict, nullable=False)
    endpoints = Column(JSON_COL, default=dict, nullable=False)

    # Trust chain
    sponsorship_cert = Column(JSON_COL, nullable=True)
    death_cert = Column(JSON_COL, nullable=True)

    # POLIS civil standing integration
    polis_did = Column(String(255), nullable=True)
    polis_standing_score = Column(Float, nullable=True)
    polis_standing_tier = Column(String(50), nullable=True)

    # UAHP Beacon propagation
    beacon_version = Column(String(20), nullable=True)
    beacon_carried = Column(Boolean, default=False)

    # Registry endorsement
    registry_signature = Column(Text, nullable=True)

    def is_live(self) -> bool:
        return self.liveness_status == 'live'

    def has_civil_standing(self) -> bool:
        return self.polis_did is not None and self.polis_standing_score is not None

    def carries_beacon(self) -> bool:
        return self.beacon_carried is True

    def __repr__(self):
        return (
            f"<Agent {self.agent_id} "
            f"liveness={self.liveness_status} "
            f"polis_tier={self.polis_standing_tier or 'none'} "
            f"beacon={self.beacon_carried}>"
        )
