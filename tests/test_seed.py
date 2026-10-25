import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SEED_FILE = Path(__file__).resolve().parent.parent / "data" / "seed_logs.jsonl"


def load_seed():
    with open(SEED_FILE, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ingest(log: str) -> dict:
    return client.post("/ingest", json={"log": log}).json()


def test_detection_matches_labels():
    for row in load_seed():
        resp = ingest(row["log"])
        assert (resp["secrets_found"] > 0) == row["has_secret"], f"Line {row['id']}: wrong detection"


def test_secret_counts_match():
    for row in load_seed():
        resp = ingest(row["log"])
        assert resp["secrets_found"] == row["secret_count"], f"Line {row['id']}: wrong count"


def test_secret_types_match():
    for row in load_seed():
        if row["has_secret"]:
            types = {f["type"] for f in ingest(row["log"])["findings"]}
            assert types == {row["secret_type"]}, f"Line {row['id']}: wrong type"


def test_secrets_are_removed_from_output():
    for row in load_seed():
        if row["has_secret"]:
            clean = ingest(row["log"])["clean"]
            assert "eyJ" not in clean, f"Line {row['id']}: JWT still present"
            assert "AKIA" not in clean, f"Line {row['id']}: AWS key still present"
            assert "[REDACTED:" in clean


def test_normal_lines_are_unchanged():
    for row in load_seed():
        if not row["has_secret"]:
            assert ingest(row["log"])["clean"] == row["log"], f"Line {row['id']}: was modified"


def test_request_id_survives_next_to_token():
    row = next(r for r in load_seed() if r["id"] == 6)
    clean = ingest(row["log"])["clean"]
    assert "7c1e4a90-3b2d-4f6a-9e85-d2c0b1a47f13" in clean
    assert "token=[REDACTED:JWT]" in clean


def test_findings_never_contain_the_secret():
    for row in load_seed():
        resp = ingest(row["log"])
        for finding in resp["findings"]:
            assert set(finding.keys()) == {"type", "rule"}
