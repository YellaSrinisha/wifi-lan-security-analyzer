import ipaddress
import uuid
import subprocess
import os
from datetime import datetime, timezone
from typing import Optional

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ── Auto-add Nmap to PATH on Windows ─────────────────────────────────────────
_NMAP_WINDOWS_PATH = r"C:\Program Files (x86)\Nmap"
if os.name == "nt" and os.path.isdir(_NMAP_WINDOWS_PATH):
    os.environ["PATH"] = _NMAP_WINDOWS_PATH + os.pathsep + os.environ.get("PATH", "")

# In-memory stores (fallback, reset on server restart)
_scan_history: list[dict] = []
_devices: dict[str, dict] = {}

MAX_SUBNET_HOSTS = 256
MAX_PORTS = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_private_subnet(subnet_str: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.IPv4Network(subnet_str.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid subnet format: {e}")
    if network.version != 4:
        raise ValueError("Only IPv4 subnets are supported")
    if network.is_loopback:
        raise ValueError("Loopback subnets are not allowed")
    if not network.is_private:
        raise ValueError("Only private IPv4 subnets are allowed (RFC 1918)")
    if network.num_addresses > MAX_SUBNET_HOSTS:
        raise ValueError(f"Subnet too large: {network.num_addresses} addresses (max {MAX_SUBNET_HOSTS})")
    return network


def validate_private_ip(ip_str: str) -> ipaddress.IPv4Address:
    try:
        addr = ipaddress.IPv4Address(ip_str.strip())
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {e}")
    if addr.version != 4:
        raise ValueError("Only IPv4 addresses are supported")
    if addr.is_loopback:
        raise ValueError("Loopback addresses are not allowed")
    if not addr.is_private:
        raise ValueError("Only private IPv4 addresses are allowed (RFC 1918)")
    return addr


def validate_ports(ports: list[int]) -> list[int]:
    if not ports:
        raise ValueError("Port list must not be empty")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports: max {MAX_PORTS}")
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Invalid port {p}: must be between 1 and 65535")
    return ports


def check_nmap_available() -> bool:
    if not NMAP_AVAILABLE:
        return False
    try:
        nm = nmap.PortScanner()
        nm.nmap_version()
        return True
    except Exception:
        return False


def _store_scan(entry: dict) -> None:
    _scan_history.append(entry)
    if len(_scan_history) > 50:
        _scan_history.pop(0)


def _open_db():
    """
    Open a raw sqlite3 connection for long-running scan functions.
    Returns None silently if DB is unavailable so scans still work without DB.
    """
    try:
        from app.database.db import init_db, open_connection
        init_db()
        return open_connection()
    except Exception:
        return None


def run_host_discovery(subnet: str) -> dict:
    """Discover hosts on a validated private subnet and persist results to DB."""
    scan_id = str(uuid.uuid4())
    started_at = _now_iso()
    warnings: list[str] = [
        "Results may be incomplete: firewalls, AP isolation, sleeping devices, "
        "or insufficient permissions can prevent host discovery."
    ]

    validate_private_subnet(subnet)

    if not NMAP_AVAILABLE:
        return {
            "scan_id": scan_id, "target": subnet, "status": "error",
            "hosts": [], "started_at": started_at,
            "completed_at": _now_iso(), "warnings": ["nmap Python library not available"],
        }

    db = _open_db()
    try:
        if db is not None:
            db.execute(
                "INSERT INTO scans (scan_id, target_scope, scan_type, started_at, status) "
                "VALUES (?, ?, 'discovery', ?, 'running')",
                (scan_id, subnet, started_at),
            )
            db.commit()
    except Exception as e:
        warnings.append(f"DB warning (scan record): {e}")

    hosts: list[dict] = []
    status = "completed"
    err_msg: Optional[str] = None

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn --host-timeout 30s -T3")

        for host_ip in nm.all_hosts():
            host_info = nm[host_ip]
            addresses = host_info.get("addresses", {})
            mac = addresses.get("mac") or None
            hostnames_list = host_info.get("hostnames", [])
            hostname = hostnames_list[0].get("name") if hostnames_list and hostnames_list[0].get("name") else None
            state = host_info.get("status", {}).get("state", "unknown")

            hosts.append({"ip_address": host_ip, "mac_address": mac, "hostname": hostname, "state": state, "scan_id": scan_id})
            _devices[host_ip] = {"ip_address": host_ip, "mac_address": mac, "hostname": hostname, "state": state, "last_seen": _now_iso(), "scan_id": scan_id}

            if db is not None:
                try:
                    from app.services.inventory_service import upsert_device
                    upsert_device(db, host_ip, mac, hostname, scan_id)
                    db.commit()
                except Exception as e:
                    warnings.append(f"DB warning (device {host_ip}): {e}")

        completed_at = _now_iso()

        if db is not None:
            try:
                db.execute(
                    "UPDATE scans SET status='completed', completed_at=?, host_count=? WHERE scan_id=?",
                    (completed_at, len(hosts), scan_id),
                )
                db.commit()
            except Exception as e:
                warnings.append(f"DB warning (scan update): {e}")

            try:
                from app.services.risk_engine import run_risk_engine
                from app.services.score_service import calculate_score_for_scan, save_score
                findings = run_risk_engine(db, scan_id)
                db.commit()
                score_dict = calculate_score_for_scan(db, scan_id)
                save_score(db, scan_id, score_dict)
                db.commit()
            except Exception as e:
                warnings.append(f"DB warning (risk/score): {e}")

    except nmap.PortScannerError as e:
        status = "error"
        err_msg = f"Nmap error: {e}"
    except PermissionError as e:
        status = "error"
        err_msg = f"Permission denied: {e}. Try running as administrator."
    except subprocess.TimeoutExpired:
        status = "timed_out"
        err_msg = "Scan timed out."
    except Exception as e:
        status = "error"
        err_msg = f"Unexpected error: {e}"
    finally:
        if db is not None:
            try:
                if err_msg:
                    db.execute(
                        "UPDATE scans SET status=?, error_message=?, completed_at=? WHERE scan_id=?",
                        (status, err_msg, _now_iso(), scan_id),
                    )
                    db.commit()
            except Exception:
                pass
            db.close()

    if err_msg:
        warnings.append(err_msg)

    _store_scan({"scan_id": scan_id, "scan_type": "discovery", "target": subnet,
                 "status": status, "host_count": len(hosts), "started_at": started_at})

    return {
        "scan_id": scan_id, "target": subnet, "status": status,
        "hosts": hosts, "started_at": started_at,
        "completed_at": _now_iso(), "warnings": warnings,
    }


def run_port_scan(target_ip: str, ports: list[int]) -> dict:
    """Scan TCP ports on a validated private IP address and persist results to DB."""
    scan_id = str(uuid.uuid4())
    started_at = _now_iso()
    warnings: list[str] = [
        "An open port is not automatically a vulnerability. "
        "Only scan devices you own or have explicit permission to test."
    ]

    validate_private_ip(target_ip)
    validate_ports(ports)

    if not NMAP_AVAILABLE:
        return {
            "scan_id": scan_id, "target_ip": target_ip, "status": "error",
            "ports": [], "warnings": ["nmap Python library not available"],
            "completed_at": _now_iso(),
        }

    db = _open_db()
    try:
        if db is not None:
            db.execute(
                "INSERT INTO scans (scan_id, target_scope, scan_type, started_at, status) "
                "VALUES (?, ?, 'port_scan', ?, 'running')",
                (scan_id, target_ip, started_at),
            )
            db.commit()
    except Exception as e:
        warnings.append(f"DB warning (scan record): {e}")

    port_str = ",".join(str(p) for p in ports)
    port_results: list[dict] = []
    status = "completed"
    err_msg: Optional[str] = None

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target_ip, ports=port_str, arguments="-sT -sV --version-intensity 7 --host-timeout 90s -T3")

        device_id_for_port: Optional[str] = None
        if db is not None:
            try:
                row = db.execute(
                    "SELECT device_id FROM device_observations WHERE ip_address=? ORDER BY observed_at DESC LIMIT 1",
                    (target_ip,),
                ).fetchone()
                if row:
                    device_id_for_port = row["device_id"]
            except Exception:
                pass

        # Get nmap TCP data (may be empty if host didn't respond)
        tcp_data = {}
        if target_ip in nm.all_hosts():
            tcp_data = nm[target_ip].get("tcp", {})
        else:
            warnings.append(f"Host {target_ip} did not fully respond — filtered ports shown as 'filtered'.")

        # Always include ALL requested ports in results
        # Ports missing from tcp_data were silently dropped by firewall = filtered
        for port_num in ports:
            if port_num in tcp_data:
                port_info = tcp_data[port_num]
                state = port_info.get("state", "unknown")
                service = port_info.get("name") or None
                product = port_info.get("product") or None
                version = port_info.get("version") or None
            else:
                # Nmap didn't report this port — firewall silently dropped probe
                state = "filtered"
                service = None
                product = None
                version = None

            port_results.append({
                "port": port_num,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
            })

            if db is not None:
                try:
                    db.execute(
                        "INSERT INTO port_observations "
                        "(port_observation_id, scan_id, device_id, target_ip, protocol, port_number, state, service_name, product, version_info, observed_at) "
                        "VALUES (?, ?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?)",
                        (str(uuid.uuid4()), scan_id, device_id_for_port, target_ip, port_num, state, service, product, version, _now_iso()),
                    )
                    db.commit()
                except Exception as e:
                    warnings.append(f"DB warning (port {port_num}): {e}")

        completed_at = _now_iso()

        if db is not None:
            try:
                db.execute(
                    "UPDATE scans SET status='completed', completed_at=? WHERE scan_id=?",
                    (completed_at, scan_id),
                )
                db.commit()
            except Exception as e:
                warnings.append(f"DB warning (scan update): {e}")

            try:
                from app.services.risk_engine import run_risk_engine
                from app.services.score_service import calculate_score_for_scan, save_score
                findings = run_risk_engine(db, scan_id)
                db.commit()
                score_dict = calculate_score_for_scan(db, scan_id)
                save_score(db, scan_id, score_dict)
                db.commit()
            except Exception as e:
                warnings.append(f"DB warning (risk/score): {e}")

    except nmap.PortScannerError as e:
        status = "error"
        err_msg = f"Nmap error: {e}"
    except PermissionError as e:
        status = "error"
        err_msg = f"Permission denied: {e}. Try running as administrator."
    except subprocess.TimeoutExpired:
        status = "timed_out"
        err_msg = "Port scan timed out."
    except Exception as e:
        status = "error"
        err_msg = f"Unexpected error: {e}"
    finally:
        if db is not None:
            try:
                if err_msg:
                    db.execute(
                        "UPDATE scans SET status=?, error_message=?, completed_at=? WHERE scan_id=?",
                        (status, err_msg, _now_iso(), scan_id),
                    )
                    db.commit()
            except Exception:
                pass
            db.close()

    if err_msg:
        warnings.append(err_msg)

    _store_scan({"scan_id": scan_id, "scan_type": "port_scan", "target": target_ip,
                 "status": status, "host_count": None, "started_at": started_at})

    return {
        "scan_id": scan_id, "target_ip": target_ip, "status": status,
        "ports": port_results, "warnings": warnings,
        "completed_at": _now_iso(),
    }


def get_scan_history() -> list[dict]:
    return list(_scan_history)


def get_devices() -> list[dict]:
    return list(_devices.values())
