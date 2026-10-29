"""
Report service.

Assembles a full scan report dict and generates CSV output with
formula-injection protection.
"""
import csv
import io
from typing import Optional


# Characters that can trigger formula execution in spreadsheet applications
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value) -> str:
    """
    Convert value to string and prefix with a single quote if the string
    starts with a character that could be interpreted as a formula.
    """
    s = str(value) if value is not None else ""
    if s and s[0] in _FORMULA_PREFIXES:
        return "'" + s
    return s


def build_report(conn, scan_id: str) -> Optional[dict]:
    """
    Assemble a full report for one scan.

    Returns a dict with keys: scan, devices, ports, findings, score.
    Returns None if the scan does not exist.
    """
    scan_row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if scan_row is None:
        return None

    scan = dict(scan_row)

    # Devices observed in this scan (joined to device inventory)
    dev_rows = conn.execute(
        """
        SELECT do.observation_id, do.ip_address, do.observed_at, do.host_state,
               d.device_id, d.mac_address, d.hostname, d.approval_status,
               d.first_seen, d.last_seen
        FROM device_observations do
        LEFT JOIN devices d ON do.device_id = d.device_id
        WHERE do.scan_id = ?
        ORDER BY do.observed_at
        """,
        (scan_id,),
    ).fetchall()
    devices = [dict(r) for r in dev_rows]

    # Port observations
    port_rows = conn.execute(
        """
        SELECT * FROM port_observations WHERE scan_id = ?
        ORDER BY target_ip, port_number
        """,
        (scan_id,),
    ).fetchall()
    ports = [dict(r) for r in port_rows]

    # Security findings — include deduplicated port findings from other scans
    try:
        from app.services.score_service import get_findings_for_scan
        findings = get_findings_for_scan(conn, scan_id)
    except Exception:
        finding_rows = conn.execute(
            "SELECT * FROM security_findings WHERE scan_id = ? ORDER BY severity, created_at",
            (scan_id,),
        ).fetchall()
        findings = [dict(r) for r in finding_rows]

    # Score (may be absent)
    score_row = conn.execute(
        "SELECT * FROM scan_scores WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    score = dict(score_row) if score_row else None

    return {
        "scan": scan,
        "devices": devices,
        "ports": ports,
        "findings": findings,
        "score": score,
    }


def build_csv(report: dict) -> str:
    """
    Generate a CSV string from a report dict.

    Each row represents a (device, port, finding) combination.
    Scan-level and device-level fields are repeated for each row.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "scan_id", "scan_type", "target_scope", "scan_status",
        "started_at", "completed_at",
        "device_id", "ip_address", "mac_address", "hostname", "approval_status",
        "port_number", "protocol", "port_state", "service_name", "product", "version_info",
        "finding_rule_id", "finding_title", "finding_severity",
        "finding_explanation", "finding_recommendation",
    ])

    scan = report.get("scan", {})
    devices = report.get("devices", [])
    ports = report.get("ports", [])
    findings = report.get("findings", [])

    def _s(v):
        return _sanitize_csv_cell(v)

    # Build device and port lookup helpers
    ports_by_device: dict = {}
    ports_no_device: list = []
    for p in ports:
        did = p.get("device_id")
        if did:
            ports_by_device.setdefault(did, []).append(p)
        else:
            ports_no_device.append(p)

    findings_by_device: dict = {}
    findings_no_device: list = []
    for f in findings:
        did = f.get("device_id")
        if did:
            findings_by_device.setdefault(did, []).append(f)
        else:
            findings_no_device.append(f)

    def scan_cols():
        return [
            _s(scan.get("scan_id")),
            _s(scan.get("scan_type")),
            _s(scan.get("target_scope")),
            _s(scan.get("status")),
            _s(scan.get("started_at")),
            _s(scan.get("completed_at")),
        ]

    written = False

    for dev in devices:
        did = dev.get("device_id", "")
        dev_cols = [
            _s(did),
            _s(dev.get("ip_address")),
            _s(dev.get("mac_address")),
            _s(dev.get("hostname")),
            _s(dev.get("approval_status")),
        ]
        dev_ports = ports_by_device.get(did, [])
        dev_findings = findings_by_device.get(did, [])

        combos = [(p, f) for p in dev_ports for f in dev_findings] if dev_ports and dev_findings else []
        if not combos and dev_ports:
            combos = [(p, None) for p in dev_ports]
        if not combos and dev_findings:
            combos = [(None, f) for f in dev_findings]
        if not combos:
            combos = [(None, None)]

        for port, finding in combos:
            port_cols = [
                _s(port.get("port_number") if port else ""),
                _s(port.get("protocol") if port else ""),
                _s(port.get("state") if port else ""),
                _s(port.get("service_name") if port else ""),
                _s(port.get("product") if port else ""),
                _s(port.get("version_info") if port else ""),
            ]
            finding_cols = [
                _s(finding.get("rule_id") if finding else ""),
                _s(finding.get("title") if finding else ""),
                _s(finding.get("severity") if finding else ""),
                _s(finding.get("explanation") if finding else ""),
                _s(finding.get("recommendation") if finding else ""),
            ]
            writer.writerow(scan_cols() + dev_cols + port_cols + finding_cols)
            written = True

    # Scan-level findings (no device)
    for finding in findings_no_device:
        finding_cols = [
            _s(finding.get("rule_id")),
            _s(finding.get("title")),
            _s(finding.get("severity")),
            _s(finding.get("explanation")),
            _s(finding.get("recommendation")),
        ]
        empty_device = ["", "", "", "", ""]
        empty_port = ["", "", "", "", "", ""]
        writer.writerow(scan_cols() + empty_device + empty_port + finding_cols)
        written = True

    # If nothing at all, write one summary row
    if not written:
        writer.writerow(scan_cols() + [""] * 16)

    return output.getvalue()
