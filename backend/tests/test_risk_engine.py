"""
Tests for the security risk engine rules.
"""
import uuid
import pytest
from app.database.db import get_connection
from app.services.inventory_service import upsert_device
from app.services.risk_engine import run_risk_engine


def _iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _seed_scan(conn, scan_id, status="completed", target="192.168.1.0/24", scan_type="discovery"):
    conn.execute(
        "INSERT OR IGNORE INTO scans(scan_id, target_scope, scan_type, started_at, status) "
        "VALUES(?,?,?,?,?)",
        (scan_id, target, scan_type, _iso(), status),
    )
    conn.commit()


def _add_port(conn, scan_id, target_ip, port, state="open", device_id=None):
    conn.execute(
        """
        INSERT INTO port_observations
            (port_observation_id, scan_id, device_id, target_ip,
             protocol, port_number, state, observed_at)
        VALUES (?,?,?,?,'tcp',?,?,?)
        """,
        (str(uuid.uuid4()), scan_id, device_id, target_ip, port, state, _iso()),
    )
    conn.commit()


# ── NEW_DEVICE_001 ────────────────────────────────────────────────────────────

def test_new_device_001_fires_for_pending_review(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1")
        upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:01", None, "s1")
        conn.commit()
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "NEW_DEVICE_001" in rule_ids


def test_new_device_001_not_fired_for_approved_device(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1")
        dev_id = upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:01", None, "s1")
        conn.execute(
            "UPDATE devices SET approval_status='approved' WHERE device_id=?", (dev_id,)
        )
        conn.commit()
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "NEW_DEVICE_001" not in rule_ids


# ── SENSITIVE_PORT_001 ────────────────────────────────────────────────────────

def test_sensitive_port_001_fires_for_telnet(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", scan_type="port_scan", target="192.168.1.5")
        _add_port(conn, "s1", "192.168.1.5", 23, "open")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "SENSITIVE_PORT_001" in rule_ids


def test_sensitive_port_001_not_fired_for_closed_port(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", scan_type="port_scan", target="192.168.1.5")
        _add_port(conn, "s1", "192.168.1.5", 23, "closed")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "SENSITIVE_PORT_001" not in rule_ids


def test_sensitive_port_001_not_fired_for_non_sensitive_port(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", scan_type="port_scan", target="192.168.1.5")
        _add_port(conn, "s1", "192.168.1.5", 9999, "open")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "SENSITIVE_PORT_001" not in rule_ids


# ── POLICY_PORT_001 ────────────────────────────────────────────────────────────

def test_policy_port_001_fires_for_ssh(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", scan_type="port_scan", target="192.168.1.5")
        _add_port(conn, "s1", "192.168.1.5", 22, "open")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "POLICY_PORT_001" in rule_ids


def test_policy_port_001_not_fired_for_closed_port(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", scan_type="port_scan", target="192.168.1.5")
        _add_port(conn, "s1", "192.168.1.5", 22, "closed")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "POLICY_PORT_001" not in rule_ids


# ── INCOMPLETE_SCAN_001 ───────────────────────────────────────────────────────

def test_incomplete_scan_001_fires_for_partial(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", status="partial")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "INCOMPLETE_SCAN_001" in rule_ids


def test_incomplete_scan_001_fires_for_timed_out(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", status="timed_out")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "INCOMPLETE_SCAN_001" in rule_ids


def test_incomplete_scan_001_not_fired_for_completed(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "s1", status="completed")
        findings = run_risk_engine(conn, "s1")
        conn.commit()
    rule_ids = [f["rule_id"] for f in findings]
    assert "INCOMPLETE_SCAN_001" not in rule_ids


def test_risk_engine_returns_empty_for_unknown_scan(tmp_db):
    with get_connection() as conn:
        result = run_risk_engine(conn, "nonexistent-scan")
    assert result == []
