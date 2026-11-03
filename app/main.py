from fastapi import FastAPI

from app.api.routes.health import router as health_router
from app.api.routes.repositories import router as repositories_router
from app.api.routes.scans import router as scans_router


app = FastAPI(
    title="PatchPilot AI",
    description="AI-powered vulnerability detection and automated remediation platform",
    version="0.1.0",
)

app.include_router(health_router, prefix="/api/v1")
app.include_router(repositories_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")


@app.get("/")
def root():
    return {
        "name": "PatchPilot AI",
        "status": "online",
        "version": "0.1.0",
    }