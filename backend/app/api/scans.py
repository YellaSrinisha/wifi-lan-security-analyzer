from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from app.schemas.scan import (
    DiscoveryRequest, DiscoveryResponse,
    PortScanRequest, PortScanResponse,
    ScanSummary, ScanDetail,
)
from app.services import nmap_service

router = APIRouter()


@router.post("/scans/discovery", response_model=DiscoveryResponse)
async def run_discovery(body: DiscoveryRequest):
    try:
        result = nmap_service.run_host_discovery(body.subnet)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return DiscoveryResponse(**result)


@router.post("/scans/ports", response_model=PortScanResponse)
async def run_port_scan(body: PortScanRequest):
    try:
        result = nmap_service.run_port_scan(body.target_ip, body.ports)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    return PortScanResponse(**result)


@router.get("/scans", response_model=list[ScanSummary])
async def get_scans():
    """
    Return scan history.
    Tries DB first; falls back to in-memory store.
    """
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY started_at DESC LIMIT 50"
            ).fetchall()
        if rows:
            result = []
            for row in rows:
                d = dict(row)
                result.append(ScanSummary(
                    scan_id=d["scan_id"],
                    scan_type=d.get("scan_type", ""),
                    target=d.get("target_scope", ""),
                    status=d.get("status", ""),
                    host_count=d.get("host_count"),
                    started_at=d.get("started_at"),
                    completed_at=d.get("completed_at"),
                ))
            return result
    except Exception:
        pass

    return [ScanSummary(**s) for s in nmap_service.get_scan_history()]


# ── IMPORTANT: /scans/compare MUST be registered before /scans/{scan_id} ──
@router.get("/scans/compare")
async def compare_scans(
    scan_id_a: str = Query(..., description="First scan ID"),
    scan_id_b: str = Query(..., description="Second scan ID"),
):
    """Compare two scans by their IDs, returning a diff dict."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            row_a = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id_a,)
            ).fetchone()
            row_b = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id_b,)
            ).fetchone()

            if row_a is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id_a} not found")
            if row_b is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_id_b} not found")

            devs_a = set(
                row["ip_address"]
                for row in conn.execute(
                    "SELECT ip_address FROM device_observations WHERE scan_id = ?",
                    (scan_id_a,),
                ).fetchall()
            )
            devs_b = set(
                row["ip_address"]
                for row in conn.execute(
                    "SELECT ip_address FROM device_observations WHERE scan_id = ?",
                    (scan_id_b,),
                ).fetchall()
            )

            ports_a = set(
                (row["target_ip"], row["port_number"])
                for row in conn.execute(
                    "SELECT target_ip, port_number FROM port_observations "
                    "WHERE scan_id = ? AND state = 'open'",
                    (scan_id_a,),
                ).fetchall()
            )
            ports_b = set(
                (row["target_ip"], row["port_number"])
                for row in conn.execute(
                    "SELECT target_ip, port_number FROM port_observations "
                    "WHERE scan_id = ? AND state = 'open'",
                    (scan_id_b,),
                ).fetchall()
            )

        return {
            "scan_id_a": scan_id_a,
            "scan_id_b": scan_id_b,
            "devices_added": sorted(devs_b - devs_a),
            "devices_removed": sorted(devs_a - devs_b),
            "devices_common": sorted(devs_a & devs_b),
            "ports_opened": [
                {"ip": ip, "port": port} for ip, port in sorted(ports_b - ports_a)
            ],
            "ports_closed": [
                {"ip": ip, "port": port} for ip, port in sorted(ports_a - ports_b)
            ],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    """Compare two scans by their IDs, returning a diff dict."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            row_a = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_a,)
            ).fetchone()
            row_b = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_b,)
            ).fetchone()

            if row_a is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_a} not found")
            if row_b is None:
                raise HTTPException(status_code=404, detail=f"Scan {scan_b} not found")

            # Devices in each scan
            devs_a = set(
                row["ip_address"]
                for row in conn.execute(
                    "SELECT ip_address FROM device_observations WHERE scan_id = ?",
                    (scan_a,),
                ).fetchall()
            )
            devs_b = set(
                row["ip_address"]
                for row in conn.execute(
                    "SELECT ip_address FROM device_observations WHERE scan_id = ?",
                    (scan_b,),
                ).fetchall()
            )

            # Ports in each scan
            ports_a = set(
                (row["target_ip"], row["port_number"])
                for row in conn.execute(
                    "SELECT target_ip, port_number FROM port_observations "
                    "WHERE scan_id = ? AND state = 'open'",
                    (scan_a,),
                ).fetchall()
            )
            ports_b = set(
                (row["target_ip"], row["port_number"])
                for row in conn.execute(
                    "SELECT target_ip, port_number FROM port_observations "
                    "WHERE scan_id = ? AND state = 'open'",
                    (scan_b,),
                ).fetchall()
            )

        return {
            "scan_a": scan_a,
            "scan_b": scan_b,
            "devices_added": sorted(devs_b - devs_a),
            "devices_removed": sorted(devs_a - devs_b),
            "devices_common": sorted(devs_a & devs_b),
            "ports_opened": [
                {"ip": ip, "port": port} for ip, port in sorted(ports_b - ports_a)
            ],
            "ports_closed": [
                {"ip": ip, "port": port} for ip, port in sorted(ports_a - ports_b)
            ],
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan_detail(scan_id: str):
    """Return details for a single scan including score."""
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="Scan not found")
            d = dict(row)
            score_row = conn.execute(
                "SELECT * FROM scan_scores WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            # Recalculate score using full findings (including deduped port findings)
            from app.services.score_service import calculate_score_for_scan, save_score
            score_dict = calculate_score_for_scan(conn, scan_id)
            save_score(conn, scan_id, score_dict)
            score_row = conn.execute(
                "SELECT * FROM scan_scores WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            score = dict(score_row) if score_row else None

        return ScanDetail(
            scan_id=d["scan_id"],
            scan_type=d.get("scan_type", ""),
            target=d.get("target_scope", ""),
            status=d.get("status", ""),
            host_count=d.get("host_count"),
            started_at=d.get("started_at"),
            completed_at=d.get("completed_at"),
            error_message=d.get("error_message"),
            limitations=d.get("limitations"),
            score=score,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
