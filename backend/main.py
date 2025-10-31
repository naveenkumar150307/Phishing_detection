import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict

# Allow running this file directly by adding project root to sys.path
_CURR_DIR = os.path.dirname(__file__)
_PROJ_ROOT = os.path.abspath(os.path.join(_CURR_DIR, os.pardir))
if _PROJ_ROOT not in sys.path:
    sys.path.insert(0, _PROJ_ROOT)

from src.pipeline import PhishingDetectionPipeline

app = FastAPI(title="Kago Security Backend", version="1.0.0")

# Allow Android emulator/device or browsers to call this API if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline once
pipe = PhishingDetectionPipeline()


class VerifyRequest(BaseModel):
    url: str


def map_layer2_to_status(label: str) -> str:
    if label == "Malicious SSL/DNS detected":
        return "phishing"
    if label == "Suspicious DNS or SSL anomaly":
        return "suspicious"
    # default safe
    return "legitimate"


@app.post("/verify")
async def verify(req: VerifyRequest) -> Dict[str, Any]:
    result = pipe.run(req.url)
    layer2 = result.get("layer2", {})
    label = layer2.get("label", "")
    confidence = float(layer2.get("confidence", 0.0) or 0.0)
    status = map_layer2_to_status(label)
    response = {
        "status": status,
        "confidence": confidence,
        "label": label,
        "meta": layer2.get("meta", {}),
        "final": result.get("final", {}),
    }
    return response


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def root() -> Dict[str, str]:
    return {"message": "Kago Security Backend running", "health": "/health", "verify": "/verify"}


# Optional local run: uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    # Use reload=False to avoid watcher shutdowns in some Windows IDE shells
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False, lifespan="off")
