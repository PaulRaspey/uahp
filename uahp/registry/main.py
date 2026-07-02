from fastapi import FastAPI
from fastapi.responses import JSONResponse
from .service import router, Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="UAHP-Registry",
    description="Thermodynamic-aware, liveness-native discovery layer for the UAHP agentic stack",
    version="0.1.0"
)

app.include_router(router)

@app.get("/.well-known/uahp.json")
async def well_known():
    return JSONResponse({
        "uahpVersion": "0.5.4",
        "registryEndpoint": "http://localhost:8001/registry/register",
        "supportedVersions": ["0.5.4"]
    })

@app.get("/")
async def root():
    return {"status": "UAHP-Registry v0.1 online"}
