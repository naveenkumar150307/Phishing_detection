from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import traceback
import time

try:
    # Adapt to existing function in src/ssl_dns_layer.py
    # check_ssl_dns(url: str, org_domains: Optional[List[str]] = None) -> Tuple[str, float, Dict[str, Any]]
    from src.ssl_dns_layer import check_ssl_dns as model_check
except Exception:
    def model_check(url: str):
        raise RuntimeError(
            "Could not import check_ssl_dns from src.ssl_dns_layer. "
            "Adjust import in backend/main_api.py to match your model entrypoint."
        )

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://127.0.0.1", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/check_url")
async def check_url_endpoint(req: URLRequest):
    url = req.url
    t0 = time.time()
    try:
        # Existing signature returns (label: str, confidence: float, meta: dict)
        label, confidence, meta = model_check(url)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Model error: {e}")

    label_l = str(label).lower()
    out = {
        "is_phishing": label_l in ("phishing", "malicious", "bad") or label_l.startswith("malicious"),
        "confidence": confidence,
        "reason": meta.get("reason") if isinstance(meta, dict) else None,
        "source": "ssl_dns_layer",
    }

    out["latency_ms"] = int((time.time() - t0) * 1000)
    return out

# Run with:
# (From repo root) .venv\Scripts\activate
# pip install -r backend/requirements.txt
# uvicorn backend.main_api:app --reload --port 8000
