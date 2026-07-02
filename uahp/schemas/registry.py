from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Literal
from datetime import datetime

class ThermodynamicProfile(BaseModel):
    currentPressureScore: float = Field(..., ge=0.0, le=1.0)
    breathingSupported: bool = True
    minDim: int = 8
    maxDim: int = 128
    costPerJoule: float = Field(..., gt=0)
    carbonIntensity: int = Field(..., ge=0)
    preferredSubstrates: List[str] = Field(default_factory=list)

class CSPHints(BaseModel):
    supportedEmbeddingDims: List[int] = Field(default=[8, 16, 32, 64, 128])
    fidelityTarget: float = Field(0.85, ge=0.0, le=1.0)

class Capability(BaseModel):
    id: str
    description: str
    inputSchemas: List[str] = Field(default_factory=list)
    outputSchemas: List[str] = Field(default_factory=list)
    cspCompatible: bool = True

class AgentRegistration(BaseModel):
    uahpVersion: str = "0.5.4"
    agentId: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    expiresIn: int = Field(..., gt=0)
    livenessProof: Dict
    sponsorshipCert: Optional[Dict] = None
    capabilities: List[Capability] = Field(default_factory=list)
    thermodynamicProfile: ThermodynamicProfile
    cspHints: CSPHints = Field(default_factory=CSPHints)
    endpoints: Dict[str, str]
    signature: str

class RegistryResponse(BaseModel):
    status: Literal["registered", "updated", "error"]
    agentId: str
    registryId: str
    registeredAt: datetime
    nextHeartbeatBy: datetime
    uahpWellKnown: Optional[str] = None

class DiscoveryQuery(BaseModel):
    capability: Optional[str] = None
    maxPressure: Optional[float] = Field(None, ge=0.0, le=1.0)
    maxCarbon: Optional[int] = None
    cspCompatible: Optional[bool] = None
    limit: int = Field(20, gt=0, le=100)

class DiscoveryResult(BaseModel):
    agentId: str
    capabilities: List[Capability]
    thermodynamicProfile: ThermodynamicProfile
    cspHints: CSPHints
    livenessStatus: Literal["live", "stale", "dead"]
    lastSeen: datetime
    endpoints: Dict[str, str]
