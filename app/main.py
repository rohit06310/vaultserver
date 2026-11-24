from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

from app.detectors import redact
from app import storage
from app.benchmark import run_benchmark

DASHBOARD_HTML = Path(__file__).resolve().parent / "static" / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.init_db()
    yield


app = FastAPI(title="VaultlessSecrets (MVP v0.6)", lifespan=lifespan)


class LogIn(BaseModel):
    log: str
    location: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serves the interactive security dashboard."""
    if DASHBOARD_HTML.exists():
        return FileResponse(DASHBOARD_HTML)
    return "<h1>VaultlessSecrets Dashboard</h1>"


@app.get("/benchmark")
def get_benchmark():
    """Runs a quick benchmark against labeled seed logs and returns precision/recall metrics."""
    return run_benchmark(iterations=10)


@app.post("/ingest")
def ingest(item: LogIn):
    clean, findings = redact(item.log, default_location=item.location or "raw_log")
    for f in findings:
        loc = item.location if item.location else f.get("location", "raw_log")
        storage.record_incident(
            secret_hash=f["hash"],
            secret_type=f["type"],
            rule=f["rule"],
            location=loc,
        )
    return {"clean": clean, "secrets_found": len(findings), "findings": findings}


@app.get("/incidents")
def list_incidents():
    return {"incidents": storage.get_incidents()}
