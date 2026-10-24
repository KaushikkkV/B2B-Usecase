import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator


class UserRole(StrEnum):
    ORG_ADMIN = "ORG_ADMIN"
    CASE_MANAGER = "CASE_MANAGER"
    CLIENT = "CLIENT"


TENANT_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+$")


class AuthenticatedUser(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str
    org_id: str
    role: UserRole

    @field_validator("org_id")
    @classmethod
    def validate_org_id(cls, value: str) -> str:
        if not value or not TENANT_ID_REGEX.match(value):
            raise ValueError(
                "Invalid tenant identifier: must be alphanumeric or hyphenated UUID/slug"
            )
        return value