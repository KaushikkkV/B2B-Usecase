import uuid

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import RequireRoles, get_current_user
from app.models.document import DocumentRequest, DocumentRequestStateError, DocumentStatus
from app.repositories.document import doc_repo
from app.schemas.auth import AuthenticatedUser, UserRole
from app.schemas.document import (
    DocumentRequestCreate,
    DocumentRequestResponse,
    DocumentStatusUpdate,
)

router = APIRouter(prefix="/api/v1/document-requests", tags=["Document Requests"])


@router.post(
    "",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_document_request(
    payload: DocumentRequestCreate,
    current_user: AuthenticatedUser = Depends(
        RequireRoles([UserRole.CASE_MANAGER, UserRole.ORG_ADMIN])
    ),
) -> DocumentRequest:
    doc_id = str(uuid.uuid4())
    doc = DocumentRequest(
        id=doc_id,
        org_id=current_user.org_id,
        client_id=payload.client_id,
        title=payload.title,
        status=DocumentStatus.PENDING,
    )
    doc_repo.save(doc)
    return doc


@router.patch(
    "/{doc_id}/status",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_200_OK,
)
async def update_document_status(
    doc_id: str,
    payload: DocumentStatusUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
) -> DocumentRequest:
    doc = doc_repo.get_by_id(doc_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    # Multi-tenant isolation: prevent cross-tenant access
    if doc.org_id != current_user.org_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    # Ownership check for CLIENT role
    if current_user.role == UserRole.CLIENT and doc.client_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot update requests assigned to another client",
        )

    try:
        doc.transition_to(payload.status, user_role=current_user.role.value)
        doc_repo.save(doc)
        return doc
    except DocumentRequestStateError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err