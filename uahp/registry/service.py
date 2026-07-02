from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, DateTime, Text, Enum
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
from typing import List
from uahp.schemas.registry import (
    AgentRegistration, RegistryResponse, DiscoveryQuery, DiscoveryResult,
    Capability, ThermodynamicProfile, CSPHints
)

import os

Base = declarative_base()
engine = create_engine(
    os.environ.get("UAHP_REGISTRY_DB", "sqlite:///./uahp_registry.db"),
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class AgentModel(Base):
    __tablename__ = 'agents'
    id = Column(Integer, primary_key=True)
    agent_id = Column(String(255), unique=True, index=True, nullable=False)
    pubkey = Column(String(255), nullable=False)
    registered_at = Column(DateTime(timezone=True), server_default=func.now())
    last_heartbeat = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    liveness_status = Column(Enum('live', 'stale', 'dead', name='liveness_status_enum'), default='live')
    capabilities = Column(JSON, default=list, nullable=False)
    thermo_profile = Column(JSON, default=dict, nullable=False)
    csp_hints = Column(JSON, default=dict, nullable=False)
    endpoints = Column(JSON, default=dict, nullable=False)
    sponsorship_cert = Column(JSON, nullable=True)
    death_cert = Column(JSON, nullable=True)
    registry_signature = Column(Text, nullable=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

router = APIRouter(prefix="/registry", tags=["registry"])

@router.post("/register", response_model=RegistryResponse)
async def register_agent(reg: AgentRegistration, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.agent_id == reg.agentId).first()
    expires = reg.timestamp + timedelta(seconds=reg.expiresIn)
    if agent:
        agent.thermo_profile = reg.thermodynamicProfile.model_dump()
        agent.csp_hints = reg.cspHints.model_dump()
        agent.capabilities = [c.model_dump() for c in reg.capabilities]
        agent.expires_at = expires
        agent.liveness_status = "live"
        status = "updated"
    else:
        agent = AgentModel(
            agent_id=reg.agentId,
            pubkey=reg.agentId.split(":")[-1],
            capabilities=[c.model_dump() for c in reg.capabilities],
            thermo_profile=reg.thermodynamicProfile.model_dump(),
            csp_hints=reg.cspHints.model_dump(),
            endpoints=reg.endpoints,
            expires_at=expires,
            liveness_status="live"
        )
        db.add(agent)
        status = "registered"
    db.commit()
    db.refresh(agent)
    return RegistryResponse(
        status=status,
        agentId=reg.agentId,
        registryId="uahp-registry-v0.1",
        registeredAt=datetime.utcnow(),
        nextHeartbeatBy=expires,
        uahpWellKnown="http://localhost:8001/.well-known/uahp.json"
    )

@router.post("/heartbeat")
async def heartbeat(payload: dict, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.agent_id == payload.get("agentId")).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.last_heartbeat = datetime.utcnow()
    agent.expires_at = datetime.utcnow() + timedelta(seconds=3600)
    agent.liveness_status = "live"
    if "newPressureScore" in payload:
        profile = agent.thermo_profile or {}
        profile["currentPressureScore"] = payload["newPressureScore"]
        from sqlalchemy.orm.attributes import flag_modified
        agent.thermo_profile = profile
        flag_modified(agent, "thermo_profile")
    db.commit()
    return {"status": "ok", "agentId": payload.get("agentId")}

@router.post("/death")
async def receive_death_cert(cert: dict, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.agent_id == cert.get("agentId")).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.liveness_status = "dead"
    agent.death_cert = cert
    db.commit()
    return {"status": "dead", "agentId": cert.get("agentId")}

@router.get("/discover", response_model=List[DiscoveryResult])
@router.post("/discover", response_model=List[DiscoveryResult])
async def discover(query: DiscoveryQuery = DiscoveryQuery(), db: Session = Depends(get_db)):
    q = db.query(AgentModel).filter(
        AgentModel.liveness_status == "live",
        AgentModel.expires_at > datetime.utcnow()
    )
    results = q.limit(query.limit).all()
    return [DiscoveryResult(
        agentId=r.agent_id,
        capabilities=[Capability(**c) for c in r.capabilities],
        thermodynamicProfile=ThermodynamicProfile(**r.thermo_profile),
        cspHints=CSPHints(**r.csp_hints),
        livenessStatus=r.liveness_status,
        lastSeen=r.last_heartbeat or r.registered_at,
        endpoints=r.endpoints
    ) for r in results]

@router.get("/agent/{agentId}")
async def get_agent(agentId: str, db: Session = Depends(get_db)):
    agent = db.query(AgentModel).filter(AgentModel.agent_id == agentId).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent
