from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from app.schemas.report import ReportOut
from app.services.report_service import build_report, build_csv

router = APIRouter()


@router.get("/reports/{scan_id}", response_model=ReportOut)
async def get_report(scan_id: str):
    """Return full report for a scan."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            report = build_report(conn, scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ReportOut(**report)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/reports/{scan_id}/csv")
async def get_report_csv(scan_id: str):
    """Return report as a CSV file download."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            report = build_report(conn, scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        csv_content = build_csv(report)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    filename = f"report_{scan_id[:8]}.csv"
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
