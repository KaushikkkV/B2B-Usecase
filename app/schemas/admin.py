from pydantic import BaseModel, Field


class KeyRotationRequest(BaseModel):
    old_master_key: str = Field(..., min_length=32)
    new_master_key: str = Field(..., min_length=32)
    target_version: int = Field(..., ge=2)


class KeyRotationResponse(BaseModel):
    status: str
    migrated_count: int
    target_version: int