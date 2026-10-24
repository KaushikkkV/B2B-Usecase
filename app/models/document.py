from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar


class DocumentStatus(StrEnum):
    PENDING = "PENDING"
    UPLOADED = "UPLOADED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class DocumentRequestStateError(Exception):
    """Raised when an invalid state transition or unauthorized role attempts a status change."""


class DocumentRequest:
    # Explicit transition mapping: current_state -> {allowed_target_state: tuple_of_allowed_roles}
    VALID_TRANSITIONS: ClassVar[dict[DocumentStatus, dict[DocumentStatus, tuple[str, ...]]]] = {
        DocumentStatus.PENDING: {
            DocumentStatus.UPLOADED: ("CLIENT",),
        },
        DocumentStatus.UPLOADED: {
            DocumentStatus.APPROVED: ("CASE_MANAGER", "ORG_ADMIN"),
            DocumentStatus.REJECTED: ("CASE_MANAGER", "ORG_ADMIN"),
        },
        DocumentStatus.REJECTED: {
            DocumentStatus.UPLOADED: ("CLIENT",),
        },
        DocumentStatus.APPROVED: {},  # Terminal state: no outbound transitions permitted
    }

    def __init__(
        self,
        id: str,
        org_id: str,
        client_id: str,
        title: str,
        status: DocumentStatus = DocumentStatus.PENDING,
    ) -> None:
        self.id = id
        self.org_id = org_id
        self.client_id = client_id
        self.title = title
        self.status = status
        self.updated_at = datetime.now(UTC)

    def transition_to(self, target_status: DocumentStatus, user_role: str) -> None:
        allowed_targets = self.VALID_TRANSITIONS.get(self.status, {})

        if target_status not in allowed_targets:
            raise DocumentRequestStateError(
                f"Invalid transition: Cannot transition document from {self.status.value} to {target_status.value}"
            )

        authorized_roles = allowed_targets[target_status]
        if user_role not in authorized_roles:
            raise DocumentRequestStateError(
                f"Unauthorized transition: Role '{user_role}' cannot perform transition {self.status.value} -> {target_status.value}"
            )

        self.status = target_status
        self.updated_at = datetime.now(UTC)