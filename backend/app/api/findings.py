from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.schemas.findings import FindingOut

router = APIRouter()


@router.get("/findings", response_model=list[FindingOut])
async def get_findings(
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    severity: Optional[str] = Query(None, description="Filter by severity: high, medium, low, info"),
    min_severity: Optional[str] = Query(None, description="Minimum severity: high, medium, low (excludes info)"),
):
    """
    Return security findings.
    - Ordered by severity (high first) then by created_at DESC
    - Non-info findings always appear first
    - Without filters: returns all unique findings (deduplicated)
    """
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:

            # Severity ordering: high=1, medium=2, low=3, info=4
            severity_order = "CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"

            if scan_id:
                # Findings for a specific scan
                if severity:
                    rows = conn.execute(
                        f"SELECT * FROM security_findings WHERE scan_id = ? AND severity = ? "
                        f"ORDER BY {severity_order}, created_at DESC",
                        (scan_id, severity),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        f"SELECT * FROM security_findings WHERE scan_id = ? "
                        f"ORDER BY {severity_order}, created_at DESC",
                        (scan_id,),
                    ).fetchall()
            else:
                # All findings — deduplicate by dedup_key, keep most recent per key
                # Apply severity filter if provided
                if severity:
                    rows = conn.execute(
                        f"""
                        SELECT * FROM security_findings
                        WHERE severity = ?
                        AND dedup_key IN (
                            SELECT dedup_key FROM security_findings
                            GROUP BY dedup_key
                        )
                        GROUP BY dedup_key
                        ORDER BY {severity_order}, created_at DESC
                        LIMIT 500
                        """,
                        (severity,),
                    ).fetchall()
                elif min_severity == 'low':
                    # Only high, medium, low — exclude info
                    rows = conn.execute(
                        f"""
                        SELECT * FROM security_findings
                        WHERE severity IN ('high', 'medium', 'low')
                        GROUP BY dedup_key
                        ORDER BY {severity_order}, created_at DESC
                        LIMIT 500
                        """,
                    ).fetchall()
                elif min_severity == 'medium':
                    # Only high, medium
                    rows = conn.execute(
                        f"""
                        SELECT * FROM security_findings
                        WHERE severity IN ('high', 'medium')
                        GROUP BY dedup_key
                        ORDER BY {severity_order}, created_at DESC
                        LIMIT 500
                        """,
                    ).fetchall()
                else:
                    # All findings deduplicated — non-info first, then info
                    rows = conn.execute(
                        f"""
                        SELECT * FROM security_findings
                        GROUP BY dedup_key
                        ORDER BY {severity_order}, created_at DESC
                        LIMIT 500
                        """,
                    ).fetchall()

        return [FindingOut(**dict(r)) for r in rows]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
