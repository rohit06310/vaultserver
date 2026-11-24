import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import storage

client = TestClient(app)

SEED_FILE = Path(__file__).resolve().parent.parent / "data" / "seed_logs.jsonl"


@pytest.fixture(autouse=True)
def clean_db():
    storage.init_db()
    storage.clear_incidents()
    yield
    storage.clear_incidents()


def load_seed():
    with open(SEED_FILE, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def ingest(log: str, location: str = "raw_log") -> dict:
    return client.post("/ingest", json={"log": log, "location": location}).json()


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
            assert "MyS3cretPass123" not in clean, f"Line {row['id']}: Postgres password still present"
            assert "SuperSecretMongoPwd!" not in clean, f"Line {row['id']}: Mongo password still present"
            assert "-----BEGIN" not in clean, f"Line {row['id']}: Private key header still present"
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
            assert set(finding.keys()) == {"type", "rule", "hash", "location"}
            # The hash must be a valid 64-character hex SHA-256 string
            assert len(finding["hash"]) == 64
            assert all(c in "0123456789abcdef" for c in finding["hash"])


def test_uri_redaction_preserves_connection_context():
    row = next(r for r in load_seed() if r["id"] == 10)
    clean = ingest(row["log"])["clean"]
    assert "postgres://app_user:[REDACTED:PASSWORD]@db.prod.internal:5432/orders_db" in clean


def test_incidents_recorded_in_sqlite_with_safe_metadata():
    row = next(r for r in load_seed() if r["id"] == 8)
    ingest(row["log"], location="header.auth")

    incidents = client.get("/incidents").json()["incidents"]
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["secret_type"] == "AWS_ACCESS_KEY_ID"
    assert inc["rule"] == "aws_access_key_id_v1"
    assert inc["location"] == "header.auth"
    assert inc["count"] == 1
    assert "AKIA" not in json.dumps(inc)
    assert len(inc["secret_hash"]) == 64


def test_incidents_deduplicate_and_increment_counter():
    log_line = "Error token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_test12345"
    ingest(log_line)
    ingest(log_line)
    ingest(log_line)

    incidents = client.get("/incidents").json()["incidents"]
    assert len(incidents) == 1
    assert incidents[0]["count"] == 3
    assert incidents[0]["secret_type"] == "JWT"
    assert incidents[0]["first_seen"] <= incidents[0]["last_seen"]
