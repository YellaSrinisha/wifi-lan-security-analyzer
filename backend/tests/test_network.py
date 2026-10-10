import pytest
from unittest.mock import patch, MagicMock
import socket


def _make_mock_addrs():
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = "192.168.1.100"
    addr.netmask = "255.255.255.0"
    addr.broadcast = "192.168.1.255"
    return {"Ethernet": [addr]}


def _make_mock_stats():
    stat = MagicMock()
    stat.isup = True
    return {"Ethernet": stat}


@pytest.mark.asyncio
async def test_interfaces_returns_200(client):
    with patch("app.services.network_service.psutil.net_if_addrs", return_value=_make_mock_addrs()), \
         patch("app.services.network_service.psutil.net_if_stats", return_value=_make_mock_stats()):
        response = await client.get("/api/network/interfaces")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_interfaces_returns_list(client):
    with patch("app.services.network_service.psutil.net_if_addrs", return_value=_make_mock_addrs()), \
         patch("app.services.network_service.psutil.net_if_stats", return_value=_make_mock_stats()):
        response = await client.get("/api/network/interfaces")
    data = response.json()
    assert "interfaces" in data
    assert isinstance(data["interfaces"], list)


@pytest.mark.asyncio
async def test_interfaces_returns_correct_data(client):
    with patch("app.services.network_service.psutil.net_if_addrs", return_value=_make_mock_addrs()), \
         patch("app.services.network_service.psutil.net_if_stats", return_value=_make_mock_stats()):
        response = await client.get("/api/network/interfaces")
    data = response.json()
    iface = data["interfaces"][0]
    assert iface["name"] == "Ethernet"
    assert iface["ip_address"] == "192.168.1.100"
    assert iface["is_up"] is True


@pytest.mark.asyncio
async def test_interfaces_empty_when_no_addrs(client):
    with patch("app.services.network_service.psutil.net_if_addrs", return_value={}), \
         patch("app.services.network_service.psutil.net_if_stats", return_value={}):
        response = await client.get("/api/network/interfaces")
    data = response.json()
    assert data["interfaces"] == []
