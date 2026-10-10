from pydantic import BaseModel
from typing import Optional


class FindingOut(BaseModel):
    finding_id: str
    scan_id: str
    device_id: Optional[str] = None
    rule_id: str
    title: str
    severity: str
    explanation: str
    evidence: Optional[str] = None
    recommendation: str
    created_at: str
