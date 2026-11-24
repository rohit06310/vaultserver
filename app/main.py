from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from pydantic import BaseModel

from app.detectors import redact
from app import storage


@asynccontextmanager
async def lifespan(app: FastAPI):
    storage.init_db()
    yield


app = FastAPI(title="VaultlessSecrets (MVP v0.3)", lifespan=lifespan)


class LogIn(BaseModel):
    log: str
    location: Optional[str] = "raw_log"


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest")
def ingest(item: LogIn):
    clean, findings = redact(item.log)
    for f in findings:
        loc = item.location or f.get("location", "raw_log")
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
