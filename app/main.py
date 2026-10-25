from fastapi import FastAPI
from pydantic import BaseModel

from app.detectors import redact

app = FastAPI(title="VaultlessSecrets (MVP v0.2)")


class LogIn(BaseModel):
    log: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest")
def ingest(item: LogIn):
    clean, findings = redact(item.log)
    return {"clean": clean, "secrets_found": len(findings), "findings": findings}
