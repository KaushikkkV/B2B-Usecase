from pydantic import BaseModel, ConfigDict


class PresignedUploadRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    content_type: str
    file_size_bytes: int


class PresignedUploadResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str
    object_key: str
    expires_in: int