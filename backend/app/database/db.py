"""
SQLite database layer for Wi-Fi/LAN Security Analyzer.

DB_PATH is always computed relative to this file so it resolves to
backend/data/analyzer.db regardless of the working directory.
"""
import sqlite3
import contextlib
from datetime import datetime, timezone
from pathlib import Path

# backend/app/database/db.py  →  parent.parent.parent = backend/  + data/analyzer.db
DB_PATH: Path = (
    Path(__file__).resolve().parent.parent.parent / "data" / "analyzer.db"
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextlib.contextmanager
def get_connection():
    """Open a sqlite3 connection, enforce foreign keys, and close on exit."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        yield conn
    finally:
        conn.close()


_CREATE_SCHEMA_VERSIONS = """
CREATE TABLE IF NOT EXISTS schema_versions (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
"""

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    target_scope TEXT,
    scan_type    TEXT,
    started_at   TEXT,
    completed_at TEXT,
    status       TEXT,
    error_message TEXT,
    limitations  TEXT,
    host_count   INTEGER
);
"""

_CREATE_DEVICES = """
CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    mac_address     TEXT UNIQUE,
    last_known_ip   TEXT,
    hostname        TEXT,
    first_seen      TEXT,
    last_seen       TEXT,
    approval_status TEXT DEFAULT 'pending_review',
    created_at      TEXT,
    updated_at      TEXT
);
"""

_CREATE_DEVICE_OBSERVATIONS = """
CREATE TABLE IF NOT EXISTS device_observations (
    observation_id TEXT PRIMARY KEY,
    scan_id        TEXT REFERENCES scans(scan_id),
    device_id      TEXT REFERENCES devices(device_id),
    ip_address     TEXT,
    observed_at    TEXT,
    host_state     TEXT
);
"""

_CREATE_PORT_OBSERVATIONS = """
CREATE TABLE IF NOT EXISTS port_observations (
    port_observation_id TEXT PRIMARY KEY,
    scan_id             TEXT REFERENCES scans(scan_id),
    device_id           TEXT,
    target_ip           TEXT,
    protocol            TEXT DEFAULT 'tcp',
    port_number         INTEGER,
    state               TEXT,
    service_name        TEXT,
    product             TEXT,
    version_info        TEXT,
    observed_at         TEXT
);
"""

_CREATE_SECURITY_FINDINGS = """
CREATE TABLE IF NOT EXISTS security_findings (
    finding_id     TEXT PRIMARY KEY,
    scan_id        TEXT REFERENCES scans(scan_id),
    device_id      TEXT,
    rule_id        TEXT,
    title          TEXT,
    severity       TEXT,
    explanation    TEXT,
    evidence       TEXT,
    recommendation TEXT,
    created_at     TEXT,
    dedup_key      TEXT UNIQUE
);
"""

_CREATE_SCAN_SCORES = """
CREATE TABLE IF NOT EXISTS scan_scores (
    score_id        TEXT PRIMARY KEY,
    scan_id         TEXT UNIQUE REFERENCES scans(scan_id),
    score           INTEGER,
    scoring_version INTEGER,
    provisional     INTEGER DEFAULT 0,
    explanation     TEXT,
    created_at      TEXT
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);",
    "CREATE INDEX IF NOT EXISTS idx_device_obs_scan ON device_observations(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_port_obs_scan ON port_observations(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan ON security_findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_dedup ON security_findings(dedup_key);",
]


def init_db() -> None:
    """
    Create all tables and indexes if they don't exist.
    Safe to call repeatedly — uses IF NOT EXISTS throughout.
    Inserts schema version 1 if not already present.
    """
    # Ensure the data directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with get_connection() as conn:
        try:
            with conn:
                conn.execute(_CREATE_SCHEMA_VERSIONS)
                conn.execute(_CREATE_SCANS)
                conn.execute(_CREATE_DEVICES)
                conn.execute(_CREATE_DEVICE_OBSERVATIONS)
                conn.execute(_CREATE_PORT_OBSERVATIONS)
                conn.execute(_CREATE_SECURITY_FINDINGS)
                conn.execute(_CREATE_SCAN_SCORES)
                for idx_sql in _CREATE_INDEXES:
                    conn.execute(idx_sql)
                # Record schema version 1 if not already stored
                row = conn.execute(
                    "SELECT version FROM schema_versions WHERE version = 1"
                ).fetchone()
                if row is None:
                    conn.execute(
                        "INSERT INTO schema_versions(version, applied_at) VALUES(1, ?)",
                        (_now_iso(),),
                    )
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database initialization failed: {exc}") from exc
