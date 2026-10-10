import pytest
from app.services.nmap_service import validate_private_subnet, validate_ports


def test_validate_subnet_accepts_private():
    net = validate_private_subnet("192.168.1.0/24")
    assert str(net) == "192.168.1.0/24"


def test_validate_subnet_accepts_10_x():
    net = validate_private_subnet("10.0.0.0/24")
    assert str(net) == "10.0.0.0/24"


def test_validate_subnet_rejects_public():
    with pytest.raises(ValueError, match="private"):
        validate_private_subnet("8.8.8.0/24")


def test_validate_subnet_rejects_loopback():
    with pytest.raises(ValueError, match="[Ll]oopback"):
        validate_private_subnet("127.0.0.0/8")


def test_validate_subnet_rejects_large_subnet():
    with pytest.raises(ValueError, match="[Ll]arge|too large|max"):
        validate_private_subnet("10.0.0.0/8")


def test_validate_subnet_rejects_invalid_string():
    with pytest.raises(ValueError):
        validate_private_subnet("not-a-subnet")


def test_validate_ports_accepts_valid():
    result = validate_ports([22, 80, 443])
    assert result == [22, 80, 443]


def test_validate_ports_rejects_zero():
    with pytest.raises(ValueError):
        validate_ports([0])


def test_validate_ports_rejects_too_high():
    with pytest.raises(ValueError):
        validate_ports([65536])


def test_validate_ports_rejects_too_many():
    ports = list(range(1, 52))  # 51 ports
    with pytest.raises(ValueError, match="[Tt]oo many|max"):
        validate_ports(ports)
