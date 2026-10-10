"""
Tests for the inventory service: device identity, upsert, and approval updates.
"""
import pytest
from app.database.db import get_connection
from app.services.inventory_service import (
    upsert_device,
    get_all_devices,
    get_device_by_id,
    update_approval,
    normalize_mac,
)


def _seed_scan(conn, scan_id="scan-1"):
    conn.execute(
        "INSERT OR IGNORE INTO scans(scan_id, target_scope, scan_type, started_at, status) "
        "VALUES(?,?,?,?,?)",
        (scan_id, "192.168.1.0/24", "discovery", "2024-01-01T00:00:00+00:00", "completed"),
    )
    conn.commit()


def test_new_device_gets_pending_review(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        dev_id = upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:01", "router", "scan-1")
        conn.commit()
        device = get_device_by_id(conn, dev_id)
    assert device is not None
    assert device["approval_status"] == "pending_review"


def test_same_mac_returns_same_device_id(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn, "scan-1")
        _seed_scan(conn, "scan-2")
        id1 = upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:01", "router", "scan-1")
        conn.commit()
        id2 = upsert_device(conn, "192.168.1.2", "AA:BB:CC:DD:EE:01", "router", "scan-2")
        conn.commit()
    assert id1 == id2


def test_ip_fallback_creates_separate_devices_for_different_ips(tmp_db):
    """Without MAC, different IPs should create separate devices."""
    with get_connection() as conn:
        _seed_scan(conn, "scan-1")
        _seed_scan(conn, "scan-2")
        id1 = upsert_device(conn, "192.168.1.10", None, None, "scan-1")
        conn.commit()
        id2 = upsert_device(conn, "192.168.1.20", None, None, "scan-2")
        conn.commit()
    assert id1 != id2


def test_ip_fallback_same_ip_returns_same_device(tmp_db):
    """Without MAC, same IP should return the same device."""
    with get_connection() as conn:
        _seed_scan(conn, "scan-1")
        _seed_scan(conn, "scan-2")
        id1 = upsert_device(conn, "192.168.1.10", None, None, "scan-1")
        conn.commit()
        id2 = upsert_device(conn, "192.168.1.10", None, None, "scan-2")
        conn.commit()
    assert id1 == id2


def test_update_approval_changes_status(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        dev_id = upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:FF", None, "scan-1")
        conn.commit()
        result = update_approval(conn, dev_id, "approved")
        conn.commit()
        device = get_device_by_id(conn, dev_id)
    assert result is True
    assert device["approval_status"] == "approved"


def test_update_approval_returns_false_for_missing_device(tmp_db):
    with get_connection() as conn:
        result = update_approval(conn, "no-such-id", "approved")
    assert result is False


def test_normalize_mac_broadcast_returns_none():
    assert normalize_mac("FF:FF:FF:FF:FF:FF") is None


def test_normalize_mac_none_returns_none():
    assert normalize_mac(None) is None


def test_normalize_mac_empty_returns_none():
    assert normalize_mac("") is None


def test_normalize_mac_normalizes_case_and_separator():
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"


def test_get_all_devices_returns_list(tmp_db):
    with get_connection() as conn:
        _seed_scan(conn)
        upsert_device(conn, "192.168.1.1", "00:11:22:33:44:55", "host1", "scan-1")
        conn.commit()
        devices = get_all_devices(conn)
    assert isinstance(devices, list)
    assert len(devices) >= 1
