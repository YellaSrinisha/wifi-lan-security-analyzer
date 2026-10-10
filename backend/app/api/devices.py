from fastapi import APIRouter, HTTPException
from app.schemas.scan import DeviceResponse
from app.schemas.device import DeviceDB, ApprovalUpdateRequest
from app.services import nmap_service
from app.services.inventory_service import (
    get_all_devices,
    get_device_by_id,
    update_approval,
)

router = APIRouter()


@router.get("/devices", response_model=list[DeviceDB])
async def get_devices():
    """
    Return device inventory.
    Tries the DB first; falls back to in-memory store if DB is empty/unavailable.
    """
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            db_devices = get_all_devices(conn)
        if db_devices:
            return [DeviceDB(**d) for d in db_devices]
    except Exception:
        pass

    # Fallback: convert in-memory DeviceResponse shape to DeviceDB shape
    mem_devices = nmap_service.get_devices()
    result = []
    for d in mem_devices:
        result.append(DeviceDB(
            device_id=d.get("scan_id", ""),  # best available unique id
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
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            updated = update_approval(conn, device_id, body.approval_status)
            if not updated:
                raise HTTPException(status_code=404, detail="Device not found")
            conn.commit()
            device = get_device_by_id(conn, device_id)
        return DeviceDB(**device)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
