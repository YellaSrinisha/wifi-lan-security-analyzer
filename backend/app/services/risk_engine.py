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
POLICY_PORTS = {22, 53, 80, 3306, 5432, 6379, 27017, 1433, 8080, 8443}

_SENSITIVE_PORT_NAMES = {
    21: "FTP", 23: "Telnet", 69: "TFTP", 161: "SNMP", 162: "SNMP Trap",
    512: "rexec", 513: "rlogin", 514: "rsh", 2323: "Telnet (alt)",
    3389: "RDP", 5900: "VNC", 5901: "VNC (display 1)",
}

_POLICY_PORT_NAMES = {
    22: "SSH", 53: "DNS", 80: "HTTP", 1433: "MSSQL", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP alt",
    8443: "HTTPS alt", 27017: "MongoDB",
}


HOW_TO_FIX: dict = {
    # ── Device rules ──────────────────────────────────────────────────────────
    "NEW_DEVICE_001": {
        "how_to_fix": (
            "1. Open the Devices page and locate the pending device.\n"
            "2. Identify the device using its IP address, MAC address, and hostname.\n"
            "3. If the device belongs to you or is authorised, click Approve.\n"
            "4. If the device is unrecognised, click Revoke and then block its MAC "
            "address in your router's access-control list (ACL)."
        ),
        "verification_steps": (
            "Re-run a discovery scan. This finding should not reappear for the "
            "approved device. For a revoked/blocked device, confirm it no longer "
            "appears in the scan results."
        ),
    },
    # ── Incomplete scan ────────────────────────────────────────────────────────
    "INCOMPLETE_SCAN_001": {
        "how_to_fix": (
            "1. Ensure the scanner is running with elevated privileges "
            "(Administrator on Windows, sudo on Linux/macOS).\n"
            "2. Verify network connectivity to the target subnet.\n"
            "3. Re-run the scan. If the problem persists, try reducing the "
            "target scope to a smaller range (e.g. /28 instead of /24)."
        ),
        "verification_steps": (
            "Re-run the scan and confirm the status is 'completed' with no "
            "error message. This finding should not reappear."
        ),
    },
    # ── Port 21 FTP ────────────────────────────────────────────────────────────
    "SENSITIVE_PORT_001:21": {
        "how_to_fix": (
            "1. Disable the FTP service on the host (e.g. stop the ftpd process "
            "or the Windows IIS FTP role).\n"
            "2. If file transfer is needed, replace FTP with SFTP (port 22) or "
            "FTPS (port 990).\n"
            "3. If FTP cannot be removed, restrict access by source IP using a "
            "host-based firewall rule."
        ),
        "verification_steps": (
            "Port-scan the host after the change. Port 21 should appear as "
            "closed or filtered. Re-running a full scan should produce no "
            "SENSITIVE_PORT_001 finding for port 21 on this device."
        ),
    },
    # ── Port 23 / 2323 Telnet ──────────────────────────────────────────────────
    "SENSITIVE_PORT_001:23": {
        "how_to_fix": (
            "1. Disable the Telnet service on the host.\n"
            "2. Replace with SSH (port 22) for remote administration.\n"
            "3. If the device is a router or IoT device, access its admin panel "
            "and disable Telnet in the remote-management settings."
        ),
        "verification_steps": (
            "Port-scan the host. Port 23 should be closed or filtered. "
            "Confirm SSH is available as a replacement if remote access is needed."
        ),
    },
    "SENSITIVE_PORT_001:2323": {
        "how_to_fix": (
            "1. Disable the alternate-Telnet service on the host.\n"
            "2. Replace with SSH for remote administration.\n"
            "3. On IoT/router devices, disable Telnet and enable SSH in the "
            "device's remote-management settings."
        ),
        "verification_steps": (
            "Port-scan the host. Port 2323 should be closed or filtered."
        ),
    },
    # ── Port 69 TFTP ───────────────────────────────────────────────────────────
    "SENSITIVE_PORT_001:69": {
        "how_to_fix": (
            "1. Stop and disable the TFTP service if it is not actively required.\n"
            "2. If TFTP is needed (e.g. for PXE booting), restrict access using "
            "a firewall rule to allow only the specific hosts that require it.\n"
            "3. Consider replacing with SFTP or SCP."
        ),
        "verification_steps": (
            "Port-scan the host. Port 69/UDP should be closed or filtered."
        ),
    },
    # ── Port 161/162 SNMP ──────────────────────────────────────────────────────
    "SENSITIVE_PORT_001:161": {
        "how_to_fix": (
            "1. Disable SNMP if monitoring is not in use.\n"
            "2. If SNMP is required, upgrade to SNMPv3 with authentication "
            "and privacy (AES encryption).\n"
            "3. Restrict SNMP access by source IP in the device configuration.\n"
            "4. Change the default community strings ('public'/'private')."
        ),
        "verification_steps": (
            "Port-scan the host. Port 161/UDP should be filtered. "
            "Run an SNMP walk from an unauthorised host — it should fail."
        ),
    },
    "SENSITIVE_PORT_001:162": {
        "how_to_fix": (
            "1. Disable SNMP trap receiver if not in use.\n"
            "2. If in use, restrict who may send traps via host-based firewall.\n"
            "3. Upgrade to SNMPv3."
        ),
        "verification_steps": (
            "Port-scan the host. Port 162/UDP should be filtered."
        ),
    },
    # ── Ports 512/513/514 r-services ───────────────────────────────────────────
    "SENSITIVE_PORT_001:512": {
        "how_to_fix": (
            "1. Disable rexec (port 512). It transmits credentials in plaintext.\n"
            "2. Replace with SSH key-based authentication.\n"
            "3. Remove the rsh/rexec package (e.g. `sudo apt remove rsh-server`)."
        ),
        "verification_steps": (
            "Port-scan the host. Port 512/TCP should be closed."
        ),
    },
    "SENSITIVE_PORT_001:513": {
        "how_to_fix": (
            "1. Disable rlogin (port 513). It transmits credentials in plaintext.\n"
            "2. Replace with SSH.\n"
            "3. Remove the rlogin/rsh package."
        ),
        "verification_steps": (
            "Port-scan the host. Port 513/TCP should be closed."
        ),
    },
    "SENSITIVE_PORT_001:514": {
        "how_to_fix": (
            "1. Disable rsh (port 514). It has no authentication.\n"
            "2. Replace with SSH.\n"
            "3. Remove the rsh package."
        ),
        "verification_steps": (
            "Port-scan the host. Port 514/TCP should be closed."
        ),
    },
    # ── Port 3389 RDP ──────────────────────────────────────────────────────────
    "SENSITIVE_PORT_001:3389": {
        "how_to_fix": (
            "1. Disable RDP if remote desktop is not needed "
            "(System Properties → Remote → uncheck 'Allow remote connections').\n"
            "2. If RDP is needed:\n"
            "   a. Enable Network Level Authentication (NLA).\n"
            "   b. Restrict access to specific IP addresses via Windows Firewall.\n"
            "   c. Place RDP behind a VPN — do not expose it directly to the internet.\n"
            "3. Enable account lockout policy to prevent brute-force attacks."
        ),
        "verification_steps": (
            "Port-scan the host. Port 3389 should be filtered from external hosts. "
            "Confirm RDP is only reachable through the VPN from authorised hosts."
        ),
    },
    # ── Port 5900/5901 VNC ─────────────────────────────────────────────────────
    "SENSITIVE_PORT_001:5900": {
        "how_to_fix": (
            "1. Disable VNC if not actively in use.\n"
            "2. If VNC is needed, set a strong password and enable encryption.\n"
            "3. Bind VNC to localhost only and access it via an SSH tunnel:\n"
            "   `ssh -L 5900:localhost:5900 user@host`\n"
            "4. Restrict port 5900 at the firewall to authorised IPs only."
        ),
        "verification_steps": (
            "Port-scan the host. Port 5900 should be closed or filtered from "
            "external hosts. VNC should only be accessible through the SSH tunnel."
        ),
    },
    "SENSITIVE_PORT_001:5901": {
        "how_to_fix": (
            "1. Disable VNC display 1 if not actively in use.\n"
            "2. If needed, use the same controls as port 5900 (SSH tunnel, "
            "strong password, firewall restriction)."
        ),
        "verification_steps": (
            "Port-scan the host. Port 5901 should be closed or filtered."
        ),
    },
    # ── Policy ports (POLICY_PORT_001) ─────────────────────────────────────────
    "POLICY_PORT_001:53": {
        "how_to_fix": (
            "1. Verify whether this device is supposed to be a DNS server.\n"
            "   - Your router (gateway IP) running DNS is normal.\n"
            "   - Any other device running DNS is suspicious.\n"
            "2. If this device should NOT be a DNS server:\n"
            "   a. Identify what is running on port 53 (dnsmasq, bind, etc.)\n"
            "   b. Stop and disable the DNS service.\n"
            "   c. On Linux: sudo systemctl stop dnsmasq && sudo systemctl disable dnsmasq\n"
            "   d. On Windows: check Services for DNS Client or DNS Server role\n"
            "3. If dnsmasq is detected, check its version — dnsmasq versions below 2.83\n"
            "   have known critical vulnerabilities (DNSpooq - CVE-2020-25681 to 25687).\n"
            "   Update to the latest version immediately.\n"
            "4. If DNS must remain running, restrict it to only serve your local network\n"
            "   using firewall rules — block external DNS queries."
        ),
        "verification_steps": (
            "1. Port-scan the device — port 53 should show 'closed' or 'filtered'.\n"
            "2. If DNS was kept running, verify it only responds to local network queries.\n"
            "3. Check the dnsmasq version: run 'dnsmasq --version' — should be 2.83 or newer."
        ),
    },
    "POLICY_PORT_001:22": {
        "how_to_fix": (
            "1. Ensure SSH is required on this device. If not, disable it.\n"
            "2. If SSH is needed:\n"
            "   a. Disable password authentication — use key-based auth only "
            "   (`PasswordAuthentication no` in /etc/ssh/sshd_config).\n"
            "   b. Disable root login (`PermitRootLogin no`).\n"
            "   c. Use a non-default port if the device is internet-facing.\n"
            "   d. Enable fail2ban or equivalent brute-force protection."
        ),
        "verification_steps": (
            "Attempt SSH login with a password — it should be rejected. "
            "Confirm key-based login still works. Re-scan; the finding will remain "
            "(port is still open) but the risk is mitigated."
        ),
    },
    "POLICY_PORT_001:80": {
        "how_to_fix": (
            "1. If the web service does not need to be public, disable it or "
            "restrict it to internal IPs via firewall.\n"
            "2. If HTTP is intentional, redirect all traffic to HTTPS (443):\n"
            "   - nginx: add `return 301 https://$host$request_uri;` in the "
            "   port-80 server block.\n"
            "   - Apache: add `Redirect permanent / https://yourdomain/` in the "
            "   VirtualHost.\n"
            "3. Obtain a TLS certificate (Let's Encrypt is free)."
        ),
        "verification_steps": (
            "Navigate to http://<ip> — the browser should redirect to HTTPS. "
            "Port 80 may remain open for the redirect; port 443 must also be open "
            "with a valid certificate."
        ),
    },
    "POLICY_PORT_001:3306": {
        "how_to_fix": (
            "1. MySQL/MariaDB should never be exposed to the network unless "
            "explicitly required.\n"
            "2. Bind MySQL to localhost in /etc/mysql/my.cnf:\n"
            "   `bind-address = 127.0.0.1`\n"
            "3. If remote access is needed, use an SSH tunnel instead of opening "
            "the port directly."
        ),
        "verification_steps": (
            "Port-scan the host. Port 3306 should not be reachable from other "
            "hosts on the network."
        ),
    },
    "POLICY_PORT_001:5432": {
        "how_to_fix": (
            "1. Bind PostgreSQL to localhost in postgresql.conf:\n"
            "   `listen_addresses = 'localhost'`\n"
            "2. Restrict connections in pg_hba.conf to specific IPs if remote "
            "access is truly needed.\n"
            "3. Use an SSH tunnel for any remote DBA work."
        ),
        "verification_steps": (
            "Port-scan the host. Port 5432 should not be reachable from other "
            "hosts unless explicitly allowed."
        ),
    },
    "POLICY_PORT_001:6379": {
        "how_to_fix": (
            "1. Redis has no authentication by default and must never be "
            "internet-facing.\n"
            "2. Set `bind 127.0.0.1` in redis.conf.\n"
            "3. Enable requirepass in redis.conf with a strong password.\n"
            "4. Use a firewall rule to block port 6379 from all external hosts."
        ),
        "verification_steps": (
            "Port-scan the host. Port 6379 should not be reachable from other "
            "hosts. Attempting `redis-cli -h <ip>` from another machine should time out."
        ),
    },
    "POLICY_PORT_001:27017": {
        "how_to_fix": (
            "1. MongoDB should not be internet-accessible.\n"
            "2. Set `bindIp: 127.0.0.1` in mongod.conf.\n"
            "3. Enable authentication (`security.authorization: enabled`).\n"
            "4. Block port 27017 at the firewall."
        ),
        "verification_steps": (
            "Port-scan the host. Port 27017 should not be reachable from other "
            "hosts. Attempt `mongosh --host <ip>` from another machine — it should "
            "time out or be refused."
        ),
    },
    "POLICY_PORT_001:1433": {
        "how_to_fix": (
            "1. SQL Server: disable the TCP/IP protocol in SQL Server Configuration "
            "Manager if remote access is not needed.\n"
            "2. If remote access is required, restrict the Windows Firewall rule "
            "for port 1433 to specific management IPs.\n"
            "3. Use Windows Authentication instead of SQL Authentication where "
            "possible."
        ),
        "verification_steps": (
            "Port-scan the host. Port 1433 should be filtered from all but "
            "authorised management hosts."
        ),
    },
    "POLICY_PORT_001:8080": {
        "how_to_fix": (
            "1. Determine if the application on port 8080 is intentional.\n"
            "2. If it is a development server, ensure it is not accessible on the "
            "production network.\n"
            "3. If it is a proxy or application server, ensure it requires "
            "authentication and serves over HTTPS.\n"
            "4. Restrict access to known-good IPs via firewall if the service "
            "must remain exposed."
        ),
        "verification_steps": (
            "Confirm the service on port 8080 is expected. Verify authentication "
            "is enforced. Port-scan after firewall changes to confirm restriction."
        ),
    },
    "POLICY_PORT_001:8443": {
        "how_to_fix": (
            "1. Verify the service on port 8443 is expected and authorised.\n"
            "2. Ensure TLS is properly configured with a valid certificate.\n"
            "3. Restrict access to known-good IPs if this is an administrative "
            "interface."
        ),
        "verification_steps": (
            "Confirm TLS is working: `curl -I https://<ip>:8443` should return "
            "a valid response. Port-scan after any firewall changes."
        ),
    },
}


def _get_fix_content(rule_id: str, port_number: Optional[int] = None) -> tuple:
    """
    Return (how_to_fix, verification_steps) for the given rule and port.

    Lookup order:
      1. rule_id:port_number  (port-specific key, e.g. "SENSITIVE_PORT_001:23")
      2. rule_id              (rule-level key, e.g. "NEW_DEVICE_001")
      3. empty strings        (graceful fallback for any future rules)
    """
    if port_number is not None:
        entry = HOW_TO_FIX.get(f"{rule_id}:{port_number}")
        if entry:
            return entry["how_to_fix"], entry["verification_steps"]
    entry = HOW_TO_FIX.get(rule_id)
    if entry:
        return entry["how_to_fix"], entry["verification_steps"]
    return "", ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_dedup_key(scan_id: str, device_id: Optional[str], rule_id: str, port_number: Optional[int], target_ip: Optional[str] = None) -> str:
    """
    Generate a stable dedup key.

    For port-based rules (POLICY_PORT_001, SENSITIVE_PORT_001):
        key = rule_id + target_ip + port  (NO scan_id)
        → same port on same device = same key across all scans
        → scanning the same device twice won't multiply the finding

    For device/scan rules (NEW_DEVICE_001, INCOMPLETE_SCAN_001):
        key = rule_id + scan_id + device_id
        → new device finding is per-scan (device may be approved later)
        → incomplete scan finding is per-scan
    """
    if rule_id in ("POLICY_PORT_001", "SENSITIVE_PORT_001"):
        # Network-stable key: same port on same IP = same finding forever
        raw = f"{rule_id}:{target_ip or ''}:{port_number or ''}"
    else:
        # Per-scan key: new device or incomplete scan findings are scan-specific
        raw = f"{rule_id}:{scan_id}:{device_id or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _insert_finding(conn, finding: dict) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO security_findings
            (finding_id, scan_id, device_id, rule_id, title, severity,
             explanation, evidence, recommendation, created_at, dedup_key,
             how_to_fix, verification_steps)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            finding.get("how_to_fix", ""),
            finding.get("verification_steps", ""),
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
            htf, vsteps = _get_fix_content("NEW_DEVICE_001")
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
                "how_to_fix": htf,
                "verification_steps": vsteps,
            })

    # ── Rule SENSITIVE_PORT_001: high-risk open ports ────────────────────────
    for obs in port_obs_rows:
        obs = dict(obs)
        if obs.get("state") == "open" and obs.get("port_number") in SENSITIVE_PORTS:
            port = obs["port_number"]
            device_id = obs.get("device_id")
            target_ip = obs.get("target_ip", "")
            service_label = _SENSITIVE_PORT_NAMES.get(port, f"port {port}")
            dedup = _make_dedup_key(scan_id, device_id, "SENSITIVE_PORT_001", port, target_ip)
            htf, vsteps = _get_fix_content("SENSITIVE_PORT_001", port)
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
                "how_to_fix": htf,
                "verification_steps": vsteps,
            })

    # ── Rule POLICY_PORT_001: policy-review open ports ───────────────────────
    for obs in port_obs_rows:
        obs = dict(obs)
        if obs.get("state") == "open" and obs.get("port_number") in POLICY_PORTS:
            port = obs["port_number"]
            device_id = obs.get("device_id")
            target_ip = obs.get("target_ip", "")
            service_label = _POLICY_PORT_NAMES.get(port, f"port {port}")
            dedup = _make_dedup_key(scan_id, device_id, "POLICY_PORT_001", port, target_ip)
            htf, vsteps = _get_fix_content("POLICY_PORT_001", port)
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
                "how_to_fix": htf,
                "verification_steps": vsteps,
            })

    # ── Rule INCOMPLETE_SCAN_001: scan did not complete cleanly ──────────────
    if scan.get("status") in ("partial", "timed_out", "timeout", "error"):
        dedup = _make_dedup_key(scan_id, None, "INCOMPLETE_SCAN_001", None)
        htf, vsteps = _get_fix_content("INCOMPLETE_SCAN_001")
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
            "how_to_fix": htf,
            "verification_steps": vsteps,
        })

    # Re-read all findings for this scan (includes any inserted earlier)
    rows = conn.execute(
        "SELECT * FROM security_findings WHERE scan_id = ? ORDER BY created_at",
        (scan_id,),
    ).fetchall()
    return [dict(r) for r in rows]
