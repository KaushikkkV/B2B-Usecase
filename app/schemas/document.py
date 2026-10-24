from pydantic import BaseModel, ConfigDict

from app.models.document import DocumentStatus


class DocumentRequestCreate(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    client_id: str


class DocumentStatusUpdate(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: DocumentStatus


class DocumentRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    client_id: str
    title: str
    status: DocumentStatus