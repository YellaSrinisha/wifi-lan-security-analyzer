from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.schemas.findings import FindingOut

router = APIRouter()


@router.get("/findings", response_model=list[FindingOut])
async def get_findings(scan_id: Optional[str] = Query(None, description="Filter by scan ID")):
    """Return security findings, optionally filtered by scan_id."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            if scan_id:
                rows = conn.execute(
                    "SELECT * FROM security_findings WHERE scan_id = ? ORDER BY severity, created_at",
                    (scan_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM security_findings ORDER BY created_at DESC LIMIT 200"
                ).fetchall()
        return [FindingOut(**dict(r)) for r in rows]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
