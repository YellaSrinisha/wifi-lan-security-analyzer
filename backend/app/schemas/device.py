from pydantic import BaseModel
from typing import Optional, Literal


class DeviceDB(BaseModel):
    device_id: str
    mac_address: Optional[str] = None
    last_known_ip: Optional[str] = None
    hostname: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    approval_status: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class ApprovalUpdateRequest(BaseModel):
    approval_status: Literal["approved", "revoked", "pending_review"]
