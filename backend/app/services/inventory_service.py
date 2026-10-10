"""
Device inventory service.

Maintains persistent device identity across scans using MAC address as the
primary key, with IP-address fallback when MAC is unavailable.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """
    Return MAC address in upper-case colon-separated form (AA:BB:CC:DD:EE:FF),
    or None if the input is empty, None, or a broadcast address.
    """
    if not mac:
        return None
    cleaned = mac.strip().upper().replace("-", ":").replace(".", ":")
    # Accept xx:xx:xx:xx:xx:xx or rebuild from raw hex
    parts = cleaned.split(":")
    if len(parts) != 6:
        return None
    for part in parts:
        if len(part) != 2:
            return None
        try:
            int(part, 16)
        except ValueError:
            return None
    normalized = ":".join(parts)
    # Reject broadcast address
    if normalized == "FF:FF:FF:FF:FF:FF":
        return None
    return normalized


def upsert_device(conn, ip: str, mac: Optional[str], hostname: Optional[str], scan_id: str) -> str:
    """
    Find or create a device record and record a device_observation.

    Identity strategy:
    - If a valid normalized MAC is available, look up by mac_address.
    - Otherwise look up by (mac_address IS NULL AND last_known_ip = ip).
    - Missing MAC with different IPs will create separate device records,
      preventing false merges.

    Returns the device_id (str).
    """
    norm_mac = normalize_mac(mac)
    now = _now_iso()

    device_id: Optional[str] = None

    if norm_mac is not None:
        row = conn.execute(
            "SELECT device_id FROM devices WHERE mac_address = ?",
            (norm_mac,),
        ).fetchone()
        if row:
            device_id = row["device_id"]
    else:
        row = conn.execute(
            "SELECT device_id FROM devices WHERE mac_address IS NULL AND last_known_ip = ?",
            (ip,),
        ).fetchone()
        if row:
            device_id = row["device_id"]

    if device_id is None:
        # Insert new device
        device_id = str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO devices
                (device_id, mac_address, last_known_ip, hostname,
                 first_seen, last_seen, approval_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending_review', ?, ?)
            """,
            (device_id, norm_mac, ip, hostname, now, now, now, now),
        )
    else:
        # Update mutable fields
        conn.execute(
            """
            UPDATE devices
            SET last_seen = ?,
                last_known_ip = ?,
                hostname = CASE WHEN ? IS NOT NULL THEN ? ELSE hostname END,
                updated_at = ?
            WHERE device_id = ?
            """,
            (now, ip, hostname, hostname, now, device_id),
        )

    # Always record an observation for this scan
    observation_id = str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO device_observations
            (observation_id, scan_id, device_id, ip_address, observed_at, host_state)
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (observation_id, scan_id, device_id, ip, now),
    )

    return device_id


def get_all_devices(conn) -> list[dict]:
    """Return all devices as a list of dicts."""
    rows = conn.execute("SELECT * FROM devices ORDER BY first_seen DESC").fetchall()
    return [dict(row) for row in rows]


def get_device_by_id(conn, device_id: str) -> Optional[dict]:
    """Return a single device dict or None."""
    row = conn.execute(
        "SELECT * FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()
    return dict(row) if row else None


def update_approval(conn, device_id: str, status: str) -> bool:
    """
    Update approval_status for a device.
    Returns True if a row was updated, False if device not found.
    """
    now = _now_iso()
    cursor = conn.execute(
        "UPDATE devices SET approval_status = ?, updated_at = ? WHERE device_id = ?",
        (status, now, device_id),
    )
    return cursor.rowcount > 0
