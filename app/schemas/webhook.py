from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class MalwareScanResult(StrEnum):
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"


class MalwareScanWebhookPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    document_id: str
    scan_result: MalwareScanResult
    threat_name: str | None = None