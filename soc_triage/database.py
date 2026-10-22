import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("SOC_TRIAGE_DB", ROOT / "data" / "soc_triage.db"))
MOCK_ASSETS = (
    ("lab-workstation-01", "Finance Lab Workstation"),
    ("lab-server-01", "Demo Application Server"),
)


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def initialize() -> None:
    with connect() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                description TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
            CREATE TABLE IF NOT EXISTS simulated_assets (
                asset_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                isolated INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS response_requests (
                request_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                approved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS blocked_sources (
                source_ip TEXT PRIMARY KEY,
                request_id TEXT NOT NULL REFERENCES response_requests(request_id)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                event TEXT NOT NULL,
                request_id TEXT,
                incident_id TEXT,
                details TEXT NOT NULL
            );
            """
        )
        db.executemany(
            "INSERT OR IGNORE INTO simulated_assets(asset_id, display_name) VALUES (?, ?)",
            MOCK_ASSETS,
        )
        count = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        if count == 0:
            db.executemany(
                """INSERT INTO events
                (event_id, timestamp, source_ip, asset_id, event_type, severity, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                DEMO_EVENTS,
            )


DEMO_EVENTS = (
    (
        "demo-auth-001",
        "2026-10-21T12:00:00Z",
        "198.51.100.42",
        "lab-workstation-01",
        "authentication_failure",
        6,
        "Synthetic failed sign-in for a demo account",
    ),
    (
        "demo-auth-002",
        "2026-10-21T12:03:00Z",
        "198.51.100.42",
        "lab-workstation-01",
        "authentication_failure",
        8,
        "Synthetic repeated failed sign-in for a demo account",
    ),
    (
        "demo-auth-003",
        "2026-10-21T12:06:00Z",
        "198.51.100.42",
        "lab-workstation-01",
        "authentication_failure",
        7,
        "Synthetic authentication failure in the training scenario",
    ),
    (
        "demo-scan-001",
        "2026-10-21T12:20:00Z",
        "203.0.113.77",
        "lab-server-01",
        "port_scan",
        5,
        "Synthetic connection probes against the demo service",
    ),
    (
        "demo-malware-001",
        "2026-10-21T12:30:00Z",
        "192.0.2.91",
        "lab-server-01",
        "malware_alert",
        9,
        "Synthetic endpoint rule match in the isolated training scenario",
    ),
)


def row_dict(row: sqlite3.Row) -> dict:
    return {key: row[key] for key in row.keys()}


def json_details(value: dict) -> str:
    return json.dumps(value, sort_keys=True)
