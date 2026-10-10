from pydantic import BaseModel, field_validator, model_validator
from typing import Optional


class DiscoveryRequest(BaseModel):
    subnet: str

    @field_validator('subnet')
    @classmethod
    def subnet_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('subnet must not be empty')
        return v


class DiscoveredHost(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    state: str
    scan_id: str


class DiscoveryResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    hosts: list[DiscoveredHost]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    warnings: list[str] = []


DEFAULT_PORTS = [22, 53, 80, 443, 445, 3306, 5432, 8080]
MAX_PORTS = 50


class PortScanRequest(BaseModel):
    target_ip: str
    ports: list[int] = DEFAULT_PORTS

    @field_validator('target_ip')
    @classmethod
    def target_ip_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('target_ip must not be empty')
        return v

    @field_validator('ports')
    @classmethod
    def ports_valid(cls, v: list[int]) -> list[int]:
        if not v:
            raise ValueError('ports list must not be empty')
        if len(v) > MAX_PORTS:
            raise ValueError(f'Too many ports: max {MAX_PORTS}')
        for p in v:
            if not (1 <= p <= 65535):
                raise ValueError(f'Invalid port {p}: must be between 1 and 65535')
        return v


class PortResult(BaseModel):
    port: int
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class PortScanResponse(BaseModel):
    scan_id: str
    target_ip: str
    status: str
    ports: list[PortResult]
    warnings: list[str] = []
    completed_at: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    status: str
    host_count: Optional[int] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanDetail(ScanSummary):
    """Extended scan view including error info and score."""
    error_message: Optional[str] = None
    limitations: Optional[str] = None
    score: Optional[dict] = None


class DeviceResponse(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    state: str
    last_seen: Optional[str] = None
    scan_id: str
