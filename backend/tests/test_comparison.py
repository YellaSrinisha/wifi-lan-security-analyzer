"""
Tests for the scan comparison endpoint.
"""
import uuid
import pytest


def _iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@pytest.mark.asyncio
async def test_compare_404_for_missing_scan_a(client, tmp_db):
    response = await client.get("/api/scans/compare?scan_a=no-such-a&scan_b=no-such-b")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_compare_404_for_missing_scan_b(client, tmp_db):
    from app.database.db import get_connection
    scan_id = str(uuid.uuid4())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO scans(scan_id, target_scope, scan_type, started_at, status) "
            "VALUES(?,?,?,?,?)",
            (scan_id, "192.168.1.0/24", "discovery", _iso(), "completed"),
        )
        conn.commit()
    response = await client.get(f"/api/scans/compare?scan_a={scan_id}&scan_b=no-such-b")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_compare_returns_diff_keys_for_seeded_scans(client, tmp_db):
    from app.database.db import get_connection
    from app.services.inventory_service import upsert_device

    scan_a = str(uuid.uuid4())
    scan_b = str(uuid.uuid4())

    with get_connection() as conn:
        for sid in (scan_a, scan_b):
            conn.execute(
                "INSERT INTO scans(scan_id, target_scope, scan_type, started_at, status) "
                "VALUES(?,?,?,?,?)",
                (sid, "192.168.1.0/24", "discovery", _iso(), "completed"),
            )
        conn.commit()
        # Device in scan_a only
        upsert_device(conn, "192.168.1.1", "AA:BB:CC:DD:EE:01", None, scan_a)
        # Device in both
        upsert_device(conn, "192.168.1.2", "AA:BB:CC:DD:EE:02", None, scan_a)
        upsert_device(conn, "192.168.1.2", "AA:BB:CC:DD:EE:02", None, scan_b)
        # New device in scan_b
        upsert_device(conn, "192.168.1.3", "AA:BB:CC:DD:EE:03", None, scan_b)
        conn.commit()

    response = await client.get(f"/api/scans/compare?scan_a={scan_a}&scan_b={scan_b}")
    assert response.status_code == 200
    data = response.json()
    assert "devices_added" in data
    assert "devices_removed" in data
    assert "devices_common" in data
    assert "ports_opened" in data
    assert "ports_closed" in data
    # 192.168.1.3 should appear as added
    assert "192.168.1.3" in data["devices_added"]
    # 192.168.1.1 should appear as removed
    assert "192.168.1.1" in data["devices_removed"]
    # 192.168.1.2 should be common
    assert "192.168.1.2" in data["devices_common"]
