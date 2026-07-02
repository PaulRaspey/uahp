import httpx
import hashlib
import json
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Generate a one-time key for this demo
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
pubkey_hex = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
agent_id = f"ed25519:{hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()}"

payload = {
    "uahpVersion": "0.5.4",
    "agentId": agent_id,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "expiresIn": 3600,
    "livenessProof": {"signature": "demo", "nonce": "abc123"},
    "capabilities": [{
        "id": "csp-sender",
        "description": "Cognitive State Protocol sender — iMac, ERCOT grid, 420 gCO2/kWh",
        "inputSchemas": ["application/json"],
        "outputSchemas": ["application/json"],
        "cspCompatible": True
    }],
    "thermodynamicProfile": {
        "currentPressureScore": 0.3,
        "breathingSupported": True,
        "minDim": 8,
        "maxDim": 128,
        "costPerJoule": 0.00015,
        "carbonIntensity": 420,
        "preferredSubstrates": ["local-cpu", "groq-lpu"]
    },
    "cspHints": {
        "supportedEmbeddingDims": [8, 16, 32, 64, 128],
        "fidelityTarget": 0.85
    },
    "endpoints": {
        "uahpHandshake": "http://localhost:8001/uahp/handshake",
        "smartRouter": "http://localhost:8001/smart/route",
        "cspHandoff": "http://localhost:8001/csp/transfer"
    },
    "signature": "demo-signature"
}

response = httpx.post("http://localhost:8001/registry/register", json=payload)
print(json.dumps(response.json(), indent=2))
