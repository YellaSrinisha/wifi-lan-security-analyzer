import pytest
from unittest.mock import patch


@pytest.mark.asyncio
async def test_health_returns_200(client):
    response = await client.get("/api/health")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_health_has_status_ok(client):
    response = await client.get("/api/health")
    data = response.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_health_has_nmap_available_field(client):
    response = await client.get("/api/health")
    data = response.json()
    assert "nmap_available" in data
    assert isinstance(data["nmap_available"], bool)


@pytest.mark.asyncio
async def test_health_has_version(client):
    response = await client.get("/api/health")
    data = response.json()
    assert data["version"] == "1.0.0"
