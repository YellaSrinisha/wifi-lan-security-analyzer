from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.schemas.device import DeviceDB, ApprovalUpdateRequest
from app.services import nmap_service
from app.services.inventory_service import (
    get_all_devices,
    get_device_by_id,
    update_approval,
)

router = APIRouter()


@router.get("/devices", response_model=list[DeviceDB])
async def get_devices(scan_id: Optional[str] = Query(None, description="Filter by scan ID. Use 'latest' for most recent discovery scan.")):
    """
    Return device inventory.
    - No param: all devices ever seen (full history)
    - ?scan_id=latest: only devices from the most recent discovery scan
    - ?scan_id=<uuid>: only devices from that specific scan
    """
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:

            # Resolve 'latest' to the actual most recent discovery scan_id
            if scan_id == 'latest':
                row = conn.execute(
                    "SELECT scan_id FROM scans WHERE scan_type='discovery' AND status='completed' "
                    "ORDER BY started_at DESC LIMIT 1"
                ).fetchone()
                if row:
                    scan_id = row['scan_id']
                else:
                    # No discovery scan yet — return empty list
                    return []

            if scan_id:
                # Return only devices observed in this specific scan
                rows = conn.execute(
                    """
                    SELECT d.device_id, d.mac_address, d.last_known_ip, d.hostname,
                           d.first_seen, d.last_seen, d.approval_status,
                           d.created_at, d.updated_at,
                           do.ip_address as observed_ip
                    FROM device_observations do
                    JOIN devices d ON do.device_id = d.device_id
                    WHERE do.scan_id = ?
                    ORDER BY do.observed_at ASC
                    """,
                    (scan_id,)
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    # Use the IP observed in this scan as last_known_ip
                    d['last_known_ip'] = d.get('observed_ip') or d.get('last_known_ip')
                    result.append(DeviceDB(**{k: v for k, v in d.items() if k != 'observed_ip'}))
                return result
            else:
                # Return all devices (full history)
                db_devices = get_all_devices(conn)
                if db_devices:
                    return [DeviceDB(**d) for d in db_devices]
    except Exception:
        pass

    # Fallback: in-memory store
    mem_devices = nmap_service.get_devices()
    result = []
    for d in mem_devices:
        result.append(DeviceDB(
            device_id=d.get("scan_id", ""),
            mac_address=d.get("mac_address"),
            last_known_ip=d.get("ip_address"),
            hostname=d.get("hostname"),
            last_seen=d.get("last_seen"),
            approval_status="pending_review",
        ))
    return result


@router.get("/devices/{device_id}", response_model=DeviceDB)
async def get_device(device_id: str):
    """Return a single device by ID, or 404."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            device = get_device_by_id(conn, device_id)
        if device:
            return DeviceDB(**device)
    except Exception:
        pass
    raise HTTPException(status_code=404, detail="Device not found")


@router.patch("/devices/{device_id}/approval", response_model=DeviceDB)
async def patch_approval(device_id: str, body: ApprovalUpdateRequest):
    """Update approval_status for a device."""
    from app.database.db import DB_PATH
    import sqlite3
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            cursor = conn.execute(
                "UPDATE devices SET approval_status = ?, updated_at = ? WHERE device_id = ?",
                (body.approval_status, now, device_id),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Device not found")
            conn.commit()
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Device not found after update")
            device = dict(row)
        finally:
            conn.close()
        return DeviceDB(**device)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to update approval: {exc}")
