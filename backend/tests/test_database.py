"""
Tests for the SQLite database layer: init_db idempotency, schema, FK enforcement.
"""
import sqlite3
import pytest
import app.database.db as db_module
from app.database.db import init_db, get_connection


def test_init_db_creates_tables(tmp_db):
    """All expected tables exist after init_db()."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        names = {r["name"] for r in rows}

    expected = {
        "schema_versions",
        "scans",
        "devices",
        "device_observations",
        "port_observations",
        "security_findings",
        "scan_scores",
    }
    assert expected.issubset(names)


def test_init_db_is_idempotent(tmp_db):
    """Calling init_db() a second time does not raise and preserves data."""
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scans(scan_id, target_scope, scan_type, started_at, status) "
            "VALUES('s1','192.168.1.0/24','discovery','2024-01-01T00:00:00+00:00','completed')"
        )
        conn.commit()

    # Second call should be safe
    init_db()

    with get_connection() as conn:
        row = conn.execute("SELECT scan_id FROM scans WHERE scan_id='s1'").fetchone()
    assert row is not None


def test_schema_versions_has_version_1(tmp_db):
    """schema_versions table contains version=1 after init."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT version FROM schema_versions WHERE version = 1"
        ).fetchone()
    assert row is not None
    assert row["version"] == 1


def test_foreign_key_enforcement(tmp_db):
    """Inserting a device_observation with unknown scan_id raises IntegrityError."""
    with pytest.raises(sqlite3.IntegrityError):
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO device_observations"
                "(observation_id, scan_id, device_id, ip_address, observed_at)"
                "VALUES('o1','no-such-scan','d1','1.2.3.4','2024-01-01T00:00:00+00:00')"
            )
            conn.commit()
