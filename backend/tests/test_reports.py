"""
Tests for the report service: build_report, build_csv, formula injection, 404.
"""
import pytest
from app.database.db import get_connection
from app.services.report_service import build_report, build_csv, _sanitize_csv_cell
from app.services.inventory_service import upsert_device


def _iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _seed_scan(conn, scan_id="s1", status="completed"):
    conn.execute(
        "INSERT OR IGNORE INTO scans(scan_id, target_scope, scan_type, started_at, status) "
        "VALUES(?,?,?,?,?)",
        (scan_id, "192.168.1.0/24", "discovery", _iso(), status),
    )
    conn.commit()


# ── _sanitize_csv_cell ────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad_prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_sanitize_prepends_quote_for_formula_starters(bad_prefix):
    result = _sanitize_csv_cell(f"{bad_prefix}CMD")
    assert result.startswith("'")


def test_sanitize_leaves_normal_values_unchanged():
    assert _sanitize_csv_cell("hello") == "hello"
    assert _sanitize_csv_cell(42) == "42"
    assert _sanitize_csv_cell(None) == ""


# ── build_report ─────────────────────────────────────────────────────────────

def test_build_report_returns_none_for_unknown_scan(tmp_db):
    with get_connection() as conn:
        result = build_report(conn, "no-such-scan")
    assert result is None


def test_build_report_returns_dict_with_expected_keys(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        report = build_report(conn, "s1")
    assert report is not None
    assert set(report.keys()) == {"scan", "devices", "ports", "findings", "score"}


# ── build_csv ─────────────────────────────────────────────────────────────────

def test_build_csv_returns_string(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        report = build_report(conn, "s1")
    csv_text = build_csv(report)
    assert isinstance(csv_text, str)
    assert "scan_id" in csv_text  # header present


def test_build_csv_has_header_row(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        report = build_report(conn, "s1")
    csv_text = build_csv(report)
    first_line = csv_text.splitlines()[0]
    assert "scan_id" in first_line
    assert "severity" in first_line


# ── API endpoint tests ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_report_404_for_unknown_scan(client):
    response = await client.get("/api/reports/nonexistent-scan-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_report_csv_content_type(client, tmp_db):
    """CSV endpoint should return text/csv."""
    import app.database.db as db_module
    # Seed a scan in the test DB
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scans(scan_id, target_scope, scan_type, started_at, status) "
            "VALUES('test-csv-scan','192.168.1.0/24','discovery','2024-01-01T00:00:00+00:00','completed')"
        )
        conn.commit()
    response = await client.get("/api/reports/test-csv-scan/csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
