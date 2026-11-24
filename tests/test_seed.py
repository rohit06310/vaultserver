import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import storage
from app.detectors import shannon_entropy, is_high_entropy_secret
from app.benchmark import run_benchmark

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


def ingest(log: str, location: str = None) -> dict:
    payload = {"log": log}
    if location is not None:
        payload["location"] = location
    return client.post("/ingest", json=payload).json()


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
            clean = ingest(row["log"])["clean"]
            assert clean == row["log"], f"Line {row['id']}: was modified"


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


def test_json_field_aware_redaction_and_location():
    row = next(r for r in load_seed() if r["id"] == 3)
    resp = ingest(row["log"])

    parsed_clean = json.loads(resp["clean"])
    assert parsed_clean["request"]["headers"]["Authorization"] == "Bearer [REDACTED:JWT]"
    assert parsed_clean["request"]["path"] == "/v1/orders"

    finding = resp["findings"][0]
    assert finding["location"] == "request.headers.Authorization"

    incidents = client.get("/incidents").json()["incidents"]
    assert incidents[0]["location"] == "request.headers.Authorization"


def test_json_with_arrays_and_multiple_keys():
    json_log = json.dumps({
        "service": "batch-worker",
        "tokens": [
            "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig_11111111111111111111",
            "normal-string",
            "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6Mn0.sig_22222222222222222222",
        ]
    })
    resp = ingest(json_log)
    assert resp["secrets_found"] == 2
    parsed = json.loads(resp["clean"])
    assert parsed["tokens"][0] == "[REDACTED:JWT]"
    assert parsed["tokens"][1] == "normal-string"
    assert parsed["tokens"][2] == "[REDACTED:JWT]"

    locations = {f["location"] for f in resp["findings"]}
    assert locations == {"tokens[0]", "tokens[2]"}


def test_shannon_entropy_calculation():
    # Low entropy repeated string
    assert shannon_entropy("aaaaaaaaaaaa") < 1.0
    # High entropy diverse character string
    assert shannon_entropy("xK9#mQ2$vL8*zP4!wR7&yT1@bN6%") > 4.5


def test_entropy_guard_against_false_positives():
    # Git SHA hex should not be flagged as a high entropy secret
    git_sha = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
    assert not is_high_entropy_secret(git_sha)

    # UUID should not be flagged
    uuid_str = "7c1e4a90-3b2d-4f6a-9e85-d2c0b1a47f13"
    assert not is_high_entropy_secret(uuid_str)


def test_benchmark_metrics_quality():
    metrics = run_benchmark(iterations=5)
    # Check 100% precision and recall on seed dataset
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["false_positives"] == 0
    assert metrics["false_negatives"] == 0
    assert metrics["throughput_logs_per_sec"] > 500


def test_dashboard_endpoint_serves_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "VaultlessSecrets" in resp.text
    assert "Safe Incident Ledger" in resp.text
