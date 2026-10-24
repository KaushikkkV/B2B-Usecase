from datetime import datetime
from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    id: str
    org_id: str
    document_id: str | None = None
    actor_id: str
    action: str
    details: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)