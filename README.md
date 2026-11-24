# 🛡️ VaultlessSecrets

> **Stop credentials from escaping into application logs, crash reports, and observability data.**  
> *A secret can leak after the code is already secure.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Pytest](https://img.shields.io/badge/Tests-16%20Passed-brightgreen.svg)](https://pytest.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📌 Executive Summary

**VaultlessSecrets** is a high-throughput, low-latency redaction proxy and incident intelligence ledger that sits between your microservices and your observability pipeline (Datadog, OpenSearch, Sentry, CloudWatch).

It inspects application event streams in real time, scrubs sensitive credentials (JWTs, cloud keys, database passwords, private keys, and high-entropy tokens), and records deduplicated security incidents **without ever storing or leaking the raw secret itself**.

> 💡 **Important Distinction**: VaultlessSecrets **does not replace a secrets manager** (like HashiCorp Vault or AWS Secrets Manager). Instead, it protects the **observability and telemetry boundary** where runtime credentials accidentally leak.

---

## 🚨 The Problem It Solves

Modern security tooling primarily scans source repositories:
- Pre-commit hooks (`TruffleHog`, `Gitleaks`)
- Static analysis & GitHub Secret Scanning

### The Blind Spot: Runtime Leaks
Even when source code contains **zero hardcoded credentials**, live secrets routinely escape during production runtime:

1. **The Debug Log Trap**:
   ```python
   # The code is safe, but headers contain Authorization: Bearer eyJhbGci...
   logger.info(f"Payment gateway called with headers: {headers}")
   ```
2. **Crash & Exception Dumps**:
   Database connection timeouts output full URIs with passwords:
   ```text
   FatalError: Unable to connect to postgres://app_user:MyS3cretPass@prod-db.internal:5432/orders
   ```
3. **Vendor Support Exports & CI/CD Pipelines**:
   Engineers export 50,000 log lines to share with third-party vendors (Zendesk, Datadog), unknowingly sending active API keys outside company walls.
4. **Compliance Violations**:
   Regulations like **PCI-DSS (Req 3 & 10)**, **SOC 2 Type II**, and **HIPAA** strictly penalize cleartext credentials and PAN data written to telemetry.

---

## 🏗️ System Architecture

```
                       APPLICATION LAYER
   ┌─────────────────────────────────────────────────────────┐
   │ Microservices (Go, Node, Python, Java, Docker, K8s)      │
   └────────────┬───────────────────────────────┬────────────┘
                │ stdout (Plaintext)            │ JSON Telemetry
                ▼                               ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Log Collectors / Shippers (Fluent Bit, Vector, Datadog) │
   └────────────────────────────┬────────────────────────────┘
                                │ HTTP / Stream
                                ▼
═════════════════════════════════════════════════════════════════════
               🛡️ VAULTLESSSECRETS INGESTION PROXY
═════════════════════════════════════════════════════════════════════
 1. FORMAT DETECTION
    ├── Structured JSON? ──> Recursive Object/Array Key-Path Parser
    └── Unstructured Text? ─> Regex & Context Scanner
                                │
 2. MULTI-TIER DETECTOR ENGINE
    ├── Shape Regex: JWTs (`eyJ...`), AWS Keys (`AKIA...`/`ASIA...`)
    ├── Connection URIs: PostgreSQL, MySQL, MongoDB, Redis
    ├── Cryptographic Blocks: PKCS#1, PKCS#8, EC Private Keys
    └── Shannon Entropy Filter: Random tokens (Threshold ≥ 4.3 bits)
        └── False-Positive Guards: UUIDs & Hex Git SHAs preserved
                                │
         ┌──────────────────────┴──────────────────────┐
         ▼                                             ▼
 [ SANITIZED TELEMETRY ]                      [ SAFE INCIDENT LEDGER ]
  • Useful debug context preserved             • Salted HMAC-SHA256 Hash
  • Passwords/tokens replaced with:            • Secret Type & Rule ID
    `[REDACTED:<TYPE>]`                        • Dot-notated Field Path
  • Fully valid JSON syntax preserved          • Leak Counter & Timestamps
         │                                     • ❌ Raw Secret NEVER stored
         ▼                                             │
 ┌─────────────────────────┐                           ▼
 │ Long-term Observability │                ┌──────────────────────┐
 │ (Datadog / OpenSearch)  │                │ SQLite Incident Store│
 └─────────────────────────┘                └──────────┬───────────┘
                                                       ▼
                                            ┌──────────────────────┐
                                            │ Real-Time Dashboard  │
                                            └──────────────────────┘
```

---

## ⚡ Detection Engine & Redaction Flow

| Secret Type | Detection Rule | Redaction Behavior | Preserved Context |
| :--- | :--- | :--- | :--- |
| **JWT** | `jwt_shape_v1` | `[REDACTED:JWT]` | Surrounding Bearer headers & request IDs |
| **AWS Access Key** | `aws_access_key_id_v1` | `[REDACTED:AWS_ACCESS_KEY_ID]` | Region & account context |
| **Connection String** | `uri_password_v1` | `postgres://user:[REDACTED:PASSWORD]@host:5432/db` | Protocol, user, host, port, db name |
| **Private Keys** | `private_key_block_v1` | `[REDACTED:PRIVATE_KEY]` | Service and log event metadata |
| **High-Entropy Tokens**| `entropy_token_v1` | `api_key=[REDACTED:HIGH_ENTROPY_KEY]` | Key assignment context |

### 🔒 Zero-Knowledge Incident Evidence
VaultlessSecrets **never stores the intercepted credential**. Incident evidence records only:
* `secret_hash`: Deterministic SHA-256 digest (`1a5d44a2...`) allowing security teams to correlate repeated leaks of the same token across multiple microservices.
* `secret_type`: Classification badge (`JWT`, `PASSWORD`, `AWS_ACCESS_KEY_ID`).
* `location`: Exact JSON field path (e.g. `request.headers.Authorization`) or code location.
* `count`: Aggregated leak frequency counter.
* `first_seen` / `last_seen`: ISO 8601 UTC timestamps.

---

## 📊 Benchmark & Performance

Tested on a benchmark dataset containing labeled secrets and adversarial false-positive traps (UUIDs, git commit hashes, high-cardinality order IDs):

```
=============================================
 VaultlessSecrets Detection Benchmark
=============================================
Dataset Size:           16 logs
Precision:              100.0%  (Zero false positives)
Recall:                 100.0%  (Zero missed credentials)
F1 Score:               100.0%
Throughput:             122,333+ logs/sec
Avg Overhead Latency:   0.0082 ms / log
=============================================
```

---

## 🚀 Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/rohit06310/vaultserver.git
cd vaultserver/vaultless-secrets

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Test Suite

```bash
pytest -v
```
*All 16 unit, regression, entropy, and integration tests should pass in under 1 second.*

### 3. Run Benchmark Suite

```bash
python app/benchmark.py
```

### 4. Start the Server & Open Dashboard

```bash
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

* **Interactive Web Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc API Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🔌 API Reference

### `POST /ingest`
Ingests a single log line or structured JSON string, redacts detected secrets, and records incident metrics.

**Request:**
```bash
curl -X POST http://127.0.0.1:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "log": "{\"service\":\"payment\",\"db\":\"postgres://admin:SuperPass123@db.internal:5432/app\"}"
  }'
```

**Response:**
```json
{
  "clean": "{\"service\":\"payment\",\"db\":\"postgres://admin:[REDACTED:PASSWORD]@db.internal:5432/app\"}",
  "secrets_found": 1,
  "findings": [
    {
      "type": "PASSWORD",
      "rule": "uri_password_v1",
      "hash": "b2c045...",
      "location": "db"
    }
  ]
}
```

### `GET /incidents`
Returns deduplicated incident audit records for security operations and SIEM integration.

**Response:**
```json
{
  "incidents": [
    {
      "id": 1,
      "secret_hash": "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
      "secret_type": "AWS_ACCESS_KEY_ID",
      "rule": "aws_access_key_id_v1",
      "location": "request.headers.Authorization",
      "count": 12,
      "first_seen": "2026-11-24T14:07:05.123456+00:00",
      "last_seen": "2026-11-24T14:25:12.654321+00:00"
    }
  ]
}
```

---

## 🌍 Real-World Integration Patterns

### A. Python Logging Middleware (Zero Config)
Inject into any Python application using standard library logging:
```python
import logging
from app.detectors import redact

class VaultlessFilter(logging.Filter):
    def filter(self, record):
        clean_msg, _ = redact(record.getMessage())
        record.msg = clean_msg
        record.args = ()
        return True

logging.getLogger().addFilter(VaultlessFilter())
```

### B. Daemon Log Forwarder (Fluent Bit / Vector)
Route container stdout streams through VaultlessSecrets before shipping to Datadog or OpenSearch:
```ini
[FILTER]
    Name        http
    Match       *
    Host        vaultless.internal
    Port        8000
    URI         /ingest
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
