import ipaddress
import uuid
import subprocess
from datetime import datetime, timezone
from typing import Optional

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# In-memory stores (module-level, reset on server restart)
_scan_history: list[dict] = []  # max 50 entries
_devices: dict[str, dict] = {}  # keyed by IP

MAX_SUBNET_HOSTS = 256
MAX_PORTS = 50


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_private_subnet(subnet_str: str) -> ipaddress.IPv4Network:
    """Validate that the subnet is a private IPv4 network with at most 256 hosts."""
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
        raise ValueError(
            f"Subnet too large: {network.num_addresses} addresses (max {MAX_SUBNET_HOSTS})"
        )
    return network


def validate_private_ip(ip_str: str) -> ipaddress.IPv4Address:
    """Validate that the IP is a private IPv4 address."""
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
    """Validate port list."""
    if not ports:
        raise ValueError("Port list must not be empty")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports: max {MAX_PORTS}")
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Invalid port {p}: must be between 1 and 65535")
    return ports


def check_nmap_available() -> bool:
    """Return True if nmap is importable and a PortScanner can be created."""
    if not NMAP_AVAILABLE:
        return False
    try:
        nmap.PortScanner()
        return True
    except Exception:
        return False


def _store_scan(entry: dict) -> None:
    """Append to in-memory history, capping at 50."""
    _scan_history.append(entry)
    if len(_scan_history) > 50:
        _scan_history.pop(0)


def run_host_discovery(subnet: str) -> dict:
    """Discover hosts on a validated private subnet."""
    scan_id = str(uuid.uuid4())
    started_at = _now_iso()
    warnings: list[str] = []

    try:
        validate_private_subnet(subnet)
    except ValueError as e:
        raise ValueError(str(e))

    if not NMAP_AVAILABLE:
        return {
            "scan_id": scan_id,
            "target": subnet,
            "status": "error",
            "hosts": [],
            "started_at": started_at,
            "completed_at": _now_iso(),
            "warnings": ["nmap Python library not available"],
        }

    warnings.append(
        "Results may be incomplete: firewalls, AP isolation, sleeping devices, "
        "or insufficient permissions can prevent host discovery."
    )

    # ── DB: create scan record ────────────────────────────────────────────────
    try:
        from app.database.db import init_db, get_connection
        from app.services.inventory_service import upsert_device
        from app.services.risk_engine import run_risk_engine
        from app.services.score_service import calculate_score, save_score

        init_db()
        _db_conn = get_connection().__enter__()
        _db_conn.execute(
            """
            INSERT INTO scans (scan_id, target_scope, scan_type, started_at, status)
            VALUES (?, ?, 'discovery', ?, 'running')
            """,
            (scan_id, subnet, started_at),
        )
        _db_conn.commit()
    except Exception:
        _db_conn = None

    hosts: list[dict] = []
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sn --host-timeout 30s -T3")
        for host_ip in nm.all_hosts():
            host_info = nm[host_ip]
            mac: Optional[str] = None
            hostname: Optional[str] = None
            addresses = host_info.get("addresses", {})
            if "mac" in addresses:
                mac = addresses["mac"]
            hostnames_list = host_info.get("hostnames", [])
            if hostnames_list and hostnames_list[0].get("name"):
                hostname = hostnames_list[0]["name"]
            state = host_info.get("status", {}).get("state", "unknown")
            host_entry = {
                "ip_address": host_ip,
                "mac_address": mac,
                "hostname": hostname,
                "state": state,
                "scan_id": scan_id,
            }
            hosts.append(host_entry)
            _devices[host_ip] = {
                "ip_address": host_ip,
                "mac_address": mac,
                "hostname": hostname,
                "state": state,
                "last_seen": _now_iso(),
                "scan_id": scan_id,
            }

            # ── DB: upsert device + observation ───────────────────────────────
            try:
                if _db_conn is not None:
                    upsert_device(_db_conn, host_ip, mac, hostname, scan_id)
                    _db_conn.commit()
            except Exception:
                pass

        completed_at = _now_iso()

        # ── DB: mark completed, run risk engine & score ───────────────────────
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    """
                    UPDATE scans
                    SET status='completed', completed_at=?, host_count=?
                    WHERE scan_id=?
                    """,
                    (completed_at, len(hosts), scan_id),
                )
                _db_conn.commit()
                findings = run_risk_engine(_db_conn, scan_id)
                score_dict = calculate_score(findings)
                save_score(_db_conn, scan_id, score_dict)
                _db_conn.commit()
        except Exception:
            pass

        result = {
            "scan_id": scan_id,
            "target": subnet,
            "status": "completed",
            "hosts": hosts,
            "started_at": started_at,
            "completed_at": completed_at,
            "warnings": warnings,
        }
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "discovery",
            "target": subnet,
            "status": "completed",
            "host_count": len(hosts),
            "started_at": started_at,
        })
        return result

    except nmap.PortScannerError as e:
        err_msg = f"Nmap error: {e}"
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "discovery",
            "target": subnet,
            "status": "error",
            "host_count": 0,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target": subnet,
            "status": "error",
            "hosts": [],
            "started_at": started_at,
            "completed_at": _now_iso(),
            "warnings": [err_msg],
        }
    except PermissionError as e:
        err_msg = f"Permission denied: {e}. Try running as administrator."
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "discovery",
            "target": subnet,
            "status": "error",
            "host_count": 0,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target": subnet,
            "status": "error",
            "hosts": [],
            "started_at": started_at,
            "completed_at": _now_iso(),
            "warnings": [err_msg],
        }
    except subprocess.TimeoutExpired:
        err_msg = "Scan timed out."
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='timed_out', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "discovery",
            "target": subnet,
            "status": "timeout",
            "host_count": 0,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target": subnet,
            "status": "timeout",
            "hosts": [],
            "started_at": started_at,
            "completed_at": _now_iso(),
            "warnings": [err_msg],
        }
    except Exception as e:
        err_msg = f"Unexpected error during discovery: {e}"
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "discovery",
            "target": subnet,
            "status": "error",
            "host_count": 0,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target": subnet,
            "status": "error",
            "hosts": [],
            "started_at": started_at,
            "completed_at": _now_iso(),
            "warnings": [err_msg],
        }
    finally:
        try:
            if _db_conn is not None:
                _db_conn.close()
        except Exception:
            pass


def run_port_scan(target_ip: str, ports: list[int]) -> dict:
    """Scan TCP ports on a validated private IP address."""
    scan_id = str(uuid.uuid4())
    started_at = _now_iso()
    warnings: list[str] = [
        "An open port is not automatically a vulnerability. "
        "Only scan devices you own or have explicit permission to test."
    ]

    try:
        validate_private_ip(target_ip)
        validate_ports(ports)
    except ValueError as e:
        raise ValueError(str(e))

    if not NMAP_AVAILABLE:
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "error",
            "ports": [],
            "warnings": ["nmap Python library not available"],
            "completed_at": _now_iso(),
        }

    # ── DB: create scan record ────────────────────────────────────────────────
    try:
        from app.database.db import init_db, get_connection
        from app.services.risk_engine import run_risk_engine
        from app.services.score_service import calculate_score, save_score

        init_db()
        _db_conn = get_connection().__enter__()
        _db_conn.execute(
            """
            INSERT INTO scans (scan_id, target_scope, scan_type, started_at, status)
            VALUES (?, ?, 'port_scan', ?, 'running')
            """,
            (scan_id, target_ip, started_at),
        )
        _db_conn.commit()
    except Exception:
        _db_conn = None

    port_str = ",".join(str(p) for p in ports)
    port_results: list[dict] = []
    try:
        nm = nmap.PortScanner()
        nm.scan(
            hosts=target_ip,
            ports=port_str,
            arguments="-sT -sV --host-timeout 60s -T3",
        )

        # Try to find device_id for the target IP
        device_id_for_port: Optional[str] = None
        try:
            if _db_conn is not None:
                row = _db_conn.execute(
                    "SELECT device_id FROM devices WHERE last_known_ip = ?",
                    (target_ip,),
                ).fetchone()
                if row:
                    device_id_for_port = row["device_id"]
        except Exception:
            pass

        if target_ip in nm.all_hosts():
            tcp_data = nm[target_ip].get("tcp", {})
            for port_num, port_info in tcp_data.items():
                state = port_info.get("state", "unknown")
                service = port_info.get("name") or None
                product = port_info.get("product") or None
                version = port_info.get("version") or None
                port_results.append({
                    "port": port_num,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                })
                # ── DB: insert port observation ───────────────────────────────
                try:
                    if _db_conn is not None:
                        import uuid as _uuid
                        _db_conn.execute(
                            """
                            INSERT INTO port_observations
                                (port_observation_id, scan_id, device_id, target_ip,
                                 protocol, port_number, state, service_name,
                                 product, version_info, observed_at)
                            VALUES (?, ?, ?, ?, 'tcp', ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                str(_uuid.uuid4()),
                                scan_id,
                                device_id_for_port,
                                target_ip,
                                port_num,
                                state,
                                service,
                                product,
                                version,
                                _now_iso(),
                            ),
                        )
                        _db_conn.commit()
                except Exception:
                    pass
        else:
            warnings.append(f"Host {target_ip} did not respond. It may be offline or filtered.")

        completed_at = _now_iso()

        # ── DB: mark completed, run risk engine & score ───────────────────────
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='completed', completed_at=? WHERE scan_id=?",
                    (completed_at, scan_id),
                )
                _db_conn.commit()
                findings = run_risk_engine(_db_conn, scan_id)
                score_dict = calculate_score(findings)
                save_score(_db_conn, scan_id, score_dict)
                _db_conn.commit()
        except Exception:
            pass

        _store_scan({
            "scan_id": scan_id,
            "scan_type": "port_scan",
            "target": target_ip,
            "status": "completed",
            "host_count": None,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "completed",
            "ports": port_results,
            "warnings": warnings,
            "completed_at": completed_at,
        }

    except nmap.PortScannerError as e:
        err_msg = f"Nmap error: {e}"
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "port_scan",
            "target": target_ip,
            "status": "error",
            "host_count": None,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "error",
            "ports": [],
            "warnings": [err_msg],
            "completed_at": _now_iso(),
        }
    except PermissionError as e:
        err_msg = f"Permission denied: {e}. Try running as administrator."
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "port_scan",
            "target": target_ip,
            "status": "error",
            "host_count": None,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "error",
            "ports": [],
            "warnings": [err_msg],
            "completed_at": _now_iso(),
        }
    except subprocess.TimeoutExpired:
        err_msg = "Port scan timed out."
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='timed_out', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "port_scan",
            "target": target_ip,
            "status": "timeout",
            "host_count": None,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "timeout",
            "ports": [],
            "warnings": [err_msg],
            "completed_at": _now_iso(),
        }
    except Exception as e:
        err_msg = f"Unexpected error during port scan: {e}"
        try:
            if _db_conn is not None:
                _db_conn.execute(
                    "UPDATE scans SET status='error', error_message=? WHERE scan_id=?",
                    (err_msg, scan_id),
                )
                _db_conn.commit()
        except Exception:
            pass
        _store_scan({
            "scan_id": scan_id,
            "scan_type": "port_scan",
            "target": target_ip,
            "status": "error",
            "host_count": None,
            "started_at": started_at,
        })
        return {
            "scan_id": scan_id,
            "target_ip": target_ip,
            "status": "error",
            "ports": [],
            "warnings": [err_msg],
            "completed_at": _now_iso(),
        }
    finally:
        try:
            if _db_conn is not None:
                _db_conn.close()
        except Exception:
            pass


def get_scan_history() -> list[dict]:
    return list(_scan_history)


def get_devices() -> list[dict]:
    return list(_devices.values())
