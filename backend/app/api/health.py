from fastapi import APIRouter, Query
from typing import Optional
from app.services.nmap_service import check_nmap_available

router = APIRouter()


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "nmap_available": check_nmap_available(),
        "version": "2.0.0",
    }


def _get_current_subnets() -> list[str]:
    """
    Return a list of active private IPv4 subnets the machine is currently on.
    e.g. ["192.168.1.0/24", "172.16.10.0/24"]
    Excludes loopback and link-local (169.254.x.x).
    """
    import ipaddress
    from app.services.network_service import get_network_interfaces
    subnets = []
    for iface in get_network_interfaces():
        if not iface.get("is_up"):
            continue
        ip = iface.get("ip_address")
        mask = iface.get("netmask")
        if not ip or not mask:
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_loopback or addr.is_link_local:
                continue
            if not addr.is_private:
                continue
            network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            subnets.append(str(network))
        except Exception:
            continue
    return subnets


def _ip_in_subnets(ip_str: str, subnets: list) -> bool:
    """Return True if ip_str belongs to any of the given subnets."""
    import ipaddress
    try:
        addr = ipaddress.IPv4Address(ip_str)
        for subnet in subnets:
            if addr in ipaddress.IPv4Network(subnet):
                return True
    except Exception:
        pass
    return False


@router.get("/health/score")
async def get_network_score(subnet: Optional[str] = Query(None, description="Override subnet filter")):
    """
    Return the security score for the CURRENT network only.

    Logic:
    1. Detect which private subnets the machine is currently connected to.
    2. Find the most recent discovery scan that targeted one of those subnets.
    3. Collect all scans (discovery + port scans) targeting IPs in those subnets.
    4. Count unique findings from those scans only.
    5. Calculate score from those findings.

    Pass ?subnet=192.168.1.0/24 to override the auto-detected subnet.
    """
    import ipaddress
    try:
        from app.database.db import get_connection, init_db
        init_db()
        with get_connection() as conn:

            # Step 1: determine current subnets
            if subnet:
                try:
                    current_subnets = [str(ipaddress.IPv4Network(subnet, strict=False))]
                except Exception:
                    current_subnets = []
            else:
                current_subnets = _get_current_subnets()

            if not current_subnets:
                return {
                    "score": None,
                    "breakdown": [],
                    "current_subnets": [],
                    "message": "No active private network interfaces detected. Run a scan first.",
                }

            # Step 2: find the most recent discovery scan on a current subnet
            latest_discovery = None
            all_scans = conn.execute(
                "SELECT scan_id, target_scope, scan_type, started_at FROM scans "
                "WHERE status = 'completed' ORDER BY started_at DESC LIMIT 100"
            ).fetchall()

            # Find discovery scans matching current subnets
            for row in all_scans:
                if row["scan_type"] != "discovery":
                    continue
                try:
                    scan_net = ipaddress.IPv4Network(row["target_scope"], strict=False)
                    for sub in current_subnets:
                        cur_net = ipaddress.IPv4Network(sub, strict=False)
                        # Check if the scan subnet overlaps with current subnet
                        if scan_net.overlaps(cur_net):
                            latest_discovery = row
                            break
                except Exception:
                    continue
                if latest_discovery:
                    break

            # Step 3: collect all scan IDs for the current network
            # Include port scans targeting IPs within current subnets
            relevant_scan_ids = []
            for row in all_scans:
                target = row["target_scope"]
                if not target:
                    continue
                # Discovery scan: check subnet overlap
                if row["scan_type"] == "discovery":
                    try:
                        scan_net = ipaddress.IPv4Network(target, strict=False)
                        for sub in current_subnets:
                            if scan_net.overlaps(ipaddress.IPv4Network(sub, strict=False)):
                                relevant_scan_ids.append(row["scan_id"])
                                break
                    except Exception:
                        pass
                # Port scan: check if IP is in current subnets
                elif row["scan_type"] == "port_scan":
                    if _ip_in_subnets(target, current_subnets):
                        relevant_scan_ids.append(row["scan_id"])

            if not relevant_scan_ids:
                return {
                    "score": 100,
                    "breakdown": [],
                    "current_subnets": current_subnets,
                    "latest_discovery": dict(latest_discovery) if latest_discovery else None,
                    "message": "No scans found for the current network. Run a discovery scan.",
                }

            # Step 4: count unique findings from relevant scans only
            placeholders = ",".join("?" * len(relevant_scan_ids))
            rows = conn.execute(
                f"""
                SELECT severity, COUNT(*) as cnt
                FROM (
                    SELECT severity, dedup_key
                    FROM security_findings
                    WHERE scan_id IN ({placeholders})
                    GROUP BY dedup_key
                )
                GROUP BY severity
                """,
                relevant_scan_ids,
            ).fetchall()

            # Step 5: calculate score
            deductions = {"high": 15, "medium": 8, "low": 3, "informational": 0, "info": 0}
            score = 100
            breakdown = []
            for row in rows:
                sev = row["severity"]
                count = row["cnt"]
                ded = deductions.get(sev, 0) * count
                score -= ded
                if ded > 0:
                    breakdown.append(f"{count}x {sev} (-{ded})")

            score = max(0, min(100, score))

            return {
                "score": score,
                "breakdown": breakdown,
                "current_subnets": current_subnets,
                "latest_discovery": dict(latest_discovery) if latest_discovery else None,
                "scans_included": len(relevant_scan_ids),
            }

    except Exception as exc:
        return {"score": None, "breakdown": [], "error": str(exc)}
