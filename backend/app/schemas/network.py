from pydantic import BaseModel
from typing import Optional


class NetworkInterface(BaseModel):
    name: str
    ip_address: Optional[str] = None
    netmask: Optional[str] = None
    broadcast: Optional[str] = None
    is_up: Optional[bool] = None


class InterfacesResponse(BaseModel):
    interfaces: list[NetworkInterface]
