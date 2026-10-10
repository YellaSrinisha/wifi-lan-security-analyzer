from pydantic import BaseModel
from typing import Optional


class ReportOut(BaseModel):
    scan: dict
    devices: list[dict]
    ports: list[dict]
    findings: list[dict]
    score: Optional[dict] = None
