"""SQLite storage for safe incident records.

Stores ONLY safe metadata:
- sha256_hash: one-way SHA-256 hash of the secret string (enables correlation)
- secret_type: e.g. JWT, AWS_ACCESS_KEY_ID, PASSWORD, PRIVATE_KEY
- rule: rule id that caught it
- location: location/field hint where the secret occurred
- count: occurrences of this secret
- first_seen: ISO timestamp
- last_seen: ISO timestamp

Never stores the secret itself or the full unredacted log line.
"""
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "vaultless.db"


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Initialize incident records table if not present."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                secret_hash TEXT NOT NULL UNIQUE,
                secret_type TEXT NOT NULL,
                rule TEXT NOT NULL,
                location TEXT,
                count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        conn.commit()


def record_incident(
    secret_hash: str,
    secret_type: str,
    rule: str,
    location: Optional[str] = "raw_log",
    db_path: Path = DEFAULT_DB_PATH,
) -> dict:
    """Upsert an incident record.

    If secret_hash exists, increment count and update last_seen.
    Otherwise create a new record.
    Returns the incident metadata.
    """
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO incidents (secret_hash, secret_type, rule, location, count, first_seen, last_seen)
            VALUES (?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(secret_hash) DO UPDATE SET
                count = count + 1,
                last_seen = excluded.last_seen
            RETURNING id, secret_hash, secret_type, rule, location, count, first_seen, last_seen
            """,
            (secret_hash, secret_type, rule, location, now, now),
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row)


def get_incidents(db_path: Path = DEFAULT_DB_PATH) -> list[dict]:
    """Retrieve all incident records."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(
            "SELECT id, secret_hash, secret_type, rule, location, count, first_seen, last_seen FROM incidents ORDER BY last_seen DESC"
        )
        return [dict(row) for row in cur.fetchall()]


def clear_incidents(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Clear incidents table (used by test fixtures)."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM incidents")
        conn.commit()
