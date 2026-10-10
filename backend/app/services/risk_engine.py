"""
Security risk engine.

Analyses completed scan data and produces security findings persisted to the
security_findings table. Designed to be idempotent — duplicate findings are
silently ignored via INSERT OR IGNORE + unique dedup_key.
"""
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

# Ports that are almost always security-sensitive
SENSITIVE_PORTS = {21, 23, 2323, 3389, 5900, 5901, 69, 161, 162, 512, 513, 514}

# Ports that may be legitimate but still worth flagging for review
POLICY_PORTS = {22, 80, 3306, 5432, 6379, 27017, 1433, 8080, 8443}

_SENSITIVE_PORT_NAMES = {
    21: "FTP", 23: "Telnet", 69: "TFTP", 161: "SNMP", 162: "SNMP Trap",
    512: "rexec", 513: "rlogin", 514: "rsh", 2323: "Telnet (alt)",
    3389: "RDP", 5900: "VNC", 5901: "VNC (display 1)",
}

_POLICY_PORT_NAMES = {
    22: "SSH", 80: "HTTP", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP alt",
    8443: "HTTPS alt", 27017: "MongoDB",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_dedup_key(scan_id: str, device_id: Optional[str], rule_id: str, port_number: Optional[int]) -> str:
    raw = f"{scan_id}:{device_id or ''}:{rule_id}:{port_number or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _insert_finding(conn, finding: dict) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO security_findings
            (finding_id, scan_id, device_id, rule_id, title, severity,
             explanation, evidence, recommendation, created_at, dedup_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            finding["finding_id"],
            finding["scan_id"],
            finding.get("device_id"),
            finding["rule_id"],
            finding["title"],
            finding["severity"],
            finding["explanation"],
            finding.get("evidence", ""),
            finding["recommendation"],
            finding["created_at"],
            finding["dedup_key"],
        ),
    )


def run_risk_engine(conn, scan_id: str) -> list[dict]:
    """
    Run all security rules for the given scan_id.
    Inserts findings (idempotently) and returns the full findings list.
    """
    now = _now_iso()

    # Load scan record
    scan_row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if scan_row is None:
        return []
    scan = dict(scan_row)

    # Load device observations joined with device info
    dev_obs_rows = conn.execute(
        """
        SELECT do.*, d.approval_status, d.mac_address, d.hostname
        FROM device_observations do
        LEFT JOIN devices d ON do.device_id = d.device_id
        WHERE do.scan_id = ?
        """,
        (scan_id,),
    ).fetchall()

    # Load port observations
    port_obs_rows = conn.execute(
        "SELECT * FROM port_observations WHERE scan_id = ?", (scan_id,)
    ).fetchall()

    # ── Rule NEW_DEVICE_001: pending-review devices ──────────────────────────
    for obs in dev_obs_rows:
        obs = dict(obs)
        if obs.get("approval_status") == "pending_review":
            device_id = obs["device_id"]
            ip = obs.get("ip_address", "")
            dedup = _make_dedup_key(scan_id, device_id, "NEW_DEVICE_001", None)
            _insert_finding(conn, {
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "device_id": device_id,
                "rule_id": "NEW_DEVICE_001",
                "title": "New unrecognised device detected",
                "severity": "info",
                "explanation": (
                    f"Device at {ip} has not been reviewed. "
                    "Verify this device belongs to your network."
                ),
                "evidence": f"IP: {ip}",
                "recommendation": "Review the device and approve or revoke it.",
                "created_at": now,
                "dedup_key": dedup,
            })

    # ── Rule SENSITIVE_PORT_001: high-risk open ports ────────────────────────
    for obs in port_obs_rows:
        obs = dict(obs)
        if obs.get("state") == "open" and obs.get("port_number") in SENSITIVE_PORTS:
            port = obs["port_number"]
            device_id = obs.get("device_id")
            target_ip = obs.get("target_ip", "")
            service_label = _SENSITIVE_PORT_NAMES.get(port, f"port {port}")
            dedup = _make_dedup_key(scan_id, device_id, "SENSITIVE_PORT_001", port)
            _insert_finding(conn, {
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "device_id": device_id,
                "rule_id": "SENSITIVE_PORT_001",
                "title": f"High-risk service exposed: {service_label} (port {port})",
                "severity": "high",
                "explanation": (
                    f"{service_label} (port {port}) is open on {target_ip}. "
                    "This service is commonly exploited and should be disabled or firewalled "
                    "unless strictly required."
                ),
                "evidence": f"Port {port}/{obs.get('protocol','tcp')} open on {target_ip}",
                "recommendation": (
                    f"Disable or restrict access to port {port} on {target_ip}."
                ),
                "created_at": now,
                "dedup_key": dedup,
            })

    # ── Rule POLICY_PORT_001: policy-review open ports ───────────────────────
    for obs in port_obs_rows:
        obs = dict(obs)
        if obs.get("state") == "open" and obs.get("port_number") in POLICY_PORTS:
            port = obs["port_number"]
            device_id = obs.get("device_id")
            target_ip = obs.get("target_ip", "")
            service_label = _POLICY_PORT_NAMES.get(port, f"port {port}")
            dedup = _make_dedup_key(scan_id, device_id, "POLICY_PORT_001", port)
            _insert_finding(conn, {
                "finding_id": str(uuid.uuid4()),
                "scan_id": scan_id,
                "device_id": device_id,
                "rule_id": "POLICY_PORT_001",
                "title": f"Service open for policy review: {service_label} (port {port})",
                "severity": "medium",
                "explanation": (
                    f"{service_label} (port {port}) is open on {target_ip}. "
                    "Verify this service is intentional and properly secured."
                ),
                "evidence": f"Port {port}/{obs.get('protocol','tcp')} open on {target_ip}",
                "recommendation": (
                    f"Confirm port {port} is required and apply appropriate access controls."
                ),
                "created_at": now,
                "dedup_key": dedup,
            })

    # ── Rule INCOMPLETE_SCAN_001: scan did not complete cleanly ──────────────
    if scan.get("status") in ("partial", "timed_out", "timeout", "error"):
        dedup = _make_dedup_key(scan_id, None, "INCOMPLETE_SCAN_001", None)
        _insert_finding(conn, {
            "finding_id": str(uuid.uuid4()),
            "scan_id": scan_id,
            "device_id": None,
            "rule_id": "INCOMPLETE_SCAN_001",
            "title": "Scan completed with warnings or errors",
            "severity": "low",
            "explanation": (
                f"The scan finished with status '{scan.get('status')}'. "
                "Some hosts or ports may have been missed."
            ),
            "evidence": scan.get("error_message") or scan.get("status") or "",
            "recommendation": "Re-run the scan with elevated permissions or check network connectivity.",
            "created_at": now,
            "dedup_key": dedup,
        })

    # Re-read all findings for this scan (includes any inserted earlier)
    rows = conn.execute(
        "SELECT * FROM security_findings WHERE scan_id = ? ORDER BY created_at",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]
