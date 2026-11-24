# VaultlessSecrets

Stop secrets from escaping through logs.

A secret can leak after the code is already secure. VaultlessSecrets sits between an application and its log storage, detects credentials in log events, and redacts them **before** they become permanent exposure.

> It does not replace a secret manager (like Vault). It protects the logging and observability boundary.

## Example

Before:
```
request_id=7c1e4a90 failed, token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzQyIn0.FAKEsig
```

After:
```
request_id=7c1e4a90 failed, token=[REDACTED:JWT]
```

Only the secret is removed. Useful debugging info (like the request ID) stays.

## Run it

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest                          # run the tests
uvicorn app.main:app --reload   # start the API, then open http://127.0.0.1:8000/docs
```

## API

`POST /ingest`

```json
{"log": "Using credentials aws_access_key_id=AKIAIOSFODNN7EXAMPLE"}
```

Response:

```json
{
  "clean": "Using credentials aws_access_key_id=[REDACTED:AWS_ACCESS_KEY_ID]",
  "secrets_found": 1,
  "findings": [{"type": "AWS_ACCESS_KEY_ID", "rule": "aws_access_key_id_v1"}]
}
```

Findings never contain the secret itself.

## Roadmap

- [x] Week 1: JWT detection + seed test dataset
- [x] Week 2 (part 1): AWS access key ID detection
- [x] Week 2 (part 2): passwords in connection strings, private key blocks
- [ ] Week 3: safe incident records (hash, type, location, rule, first/last seen) in SQLite
- [ ] Week 4: JSON-field-aware redaction
- [ ] Week 5: entropy check + benchmark with precision and recall
- [ ] Week 6: connect to a real app + simple dashboard

## Test data

All credentials in `data/seed_logs.jsonl` are **fake or official placeholders**. Never put real credentials in test data.
