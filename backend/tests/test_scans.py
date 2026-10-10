import pytest
from unittest.mock import patch, MagicMock


def _make_discovery_mock(hosts=None):
    """Build a mock nmap.PortScanner for host discovery."""
    if hosts is None:
        hosts = []
    nm = MagicMock()
    nm.all_hosts.return_value = [h["ip"] for h in hosts]

    def getitem(ip):
        for h in hosts:
            if h["ip"] == ip:
                return {
                    "addresses": {"ipv4": ip, **({"mac": h["mac"]} if h.get("mac") else {})},
                    "hostnames": [{"name": h.get("hostname", ""), "type": "PTR"}],
                    "status": {"state": h.get("state", "up")},
                }
        return {}

    nm.__getitem__ = MagicMock(side_effect=getitem)
    return nm


def _make_port_scan_mock(target_ip, port_data=None):
    """Build a mock nmap.PortScanner for port scanning."""
    if port_data is None:
        port_data = {}
    nm = MagicMock()
    nm.all_hosts.return_value = [target_ip]
    host_result = {
        "tcp": {
            p: {
                "state": info["state"],
                "name": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
            }
            for p, info in port_data.items()
        }
    }
    nm.__getitem__ = MagicMock(return_value=host_result)
    return nm


@pytest.mark.asyncio
async def test_discovery_valid_subnet_returns_200(client):
    with patch("app.services.nmap_service.nmap.PortScanner", return_value=_make_discovery_mock()):
        response = await client.post("/api/scans/discovery", json={"subnet": "192.168.1.0/24"})
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_discovery_public_subnet_returns_422(client):
    response = await client.post("/api/scans/discovery", json={"subnet": "8.8.8.0/24"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_discovery_invalid_subnet_returns_422(client):
    response = await client.post("/api/scans/discovery", json={"subnet": "not-valid"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_port_scan_valid_ip_returns_200(client):
    with patch("app.services.nmap_service.nmap.PortScanner", return_value=_make_port_scan_mock("192.168.1.1")):
        response = await client.post(
            "/api/scans/ports",
            json={"target_ip": "192.168.1.1", "ports": [22, 80, 443]},
        )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_port_scan_public_ip_returns_422(client):
    response = await client.post(
        "/api/scans/ports",
        json={"target_ip": "8.8.8.8", "ports": [80]},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_port_scan_invalid_port_zero_returns_422(client):
    response = await client.post(
        "/api/scans/ports",
        json={"target_ip": "192.168.1.1", "ports": [0]},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_port_scan_invalid_port_high_returns_422(client):
    response = await client.post(
        "/api/scans/ports",
        json={"target_ip": "192.168.1.1", "ports": [65536]},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_scans_returns_200_and_list(client):
    response = await client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_get_devices_returns_200_and_list(client):
    response = await client.get("/api/devices")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_discovery_returns_2_hosts(client):
    hosts = [
        {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:01", "hostname": "router", "state": "up"},
        {"ip": "192.168.1.10", "mac": None, "hostname": None, "state": "up"},
    ]
    with patch("app.services.nmap_service.nmap.PortScanner", return_value=_make_discovery_mock(hosts)):
        response = await client.post("/api/scans/discovery", json={"subnet": "192.168.1.0/24"})
    assert response.status_code == 200
    data = response.json()
    assert len(data["hosts"]) == 2
    assert data["hosts"][0]["ip_address"] == "192.168.1.1"
    assert data["hosts"][0]["mac_address"] == "AA:BB:CC:DD:EE:01"
    assert data["scan_id"] is not None
    assert data["status"] == "completed"


@pytest.mark.asyncio
async def test_port_scan_returns_3_ports(client):
    port_data = {
        22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9"},
        80: {"state": "open", "name": "http", "product": "nginx", "version": ""},
        443: {"state": "filtered", "name": "https", "product": "", "version": ""},
    }
    with patch("app.services.nmap_service.nmap.PortScanner", return_value=_make_port_scan_mock("192.168.1.1", port_data)):
        response = await client.post(
            "/api/scans/ports",
            json={"target_ip": "192.168.1.1", "ports": [22, 80, 443]},
        )
    assert response.status_code == 200
    data = response.json()
    assert len(data["ports"]) == 3
    assert data["ports"][0]["port"] == 22
    assert data["ports"][0]["state"] == "open"
    assert data["ports"][0]["service"] == "ssh"
