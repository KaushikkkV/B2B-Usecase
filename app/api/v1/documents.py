from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequireRoles, get_current_user
from app.core.database import get_db_session
from app.core.storage import StorageValidationError, storage_service
from app.models.document import DocumentRequest, DocumentRequestStateError, DocumentStatus
from app.models.sql_document import DocumentRequestModel
from app.repositories.audit import AuditRepository
from app.repositories.sql_document import SQLDocumentRepository
from app.schemas.audit import AuditEventResponse
from app.schemas.auth import AuthenticatedUser, UserRole
from app.schemas.document import (
    DocumentRequestCreate,
    DocumentRequestResponse,
    DocumentStatusUpdate,
)
from app.schemas.storage import PresignedUploadRequest, PresignedUploadResponse

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
    db: AsyncSession = Depends(get_db_session),
) -> DocumentRequestModel:
    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.create(
        org_id=current_user.org_id,
        client_id=payload.client_id,
        title=payload.title,
    )

    await audit_repo.log_event(
        org_id=current_user.org_id,
        document_id=doc.id,
        actor_id=current_user.user_id,
        action="DOCUMENT_REQUEST_CREATED",
        details=f"Title: {doc.title}, Assigned Client: {doc.client_id}",
    )

    return doc


@router.post(
    "/{doc_id}/upload-url",
    response_model=PresignedUploadResponse,
    status_code=status.HTTP_200_OK,
)
async def get_presigned_upload_url(
    doc_id: str,
    payload: PresignedUploadRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> PresignedUploadResponse:
    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.get_by_id(doc_id=doc_id, org_id=current_user.org_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    if current_user.role == UserRole.CLIENT and doc.client_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot request upload URLs for documents assigned to another client",
        )

    try:
        presigned_data = storage_service.generate_presigned_upload_url(
            org_id=doc.org_id,
            client_id=doc.client_id,
            document_id=doc.id,
            filename=payload.filename,
            content_type=payload.content_type,
            file_size_bytes=payload.file_size_bytes,
        )

        await audit_repo.log_event(
            org_id=current_user.org_id,
            document_id=doc.id,
            actor_id=current_user.user_id,
            action="UPLOAD_URL_GENERATED",
            details=f"Filename: {payload.filename}, Key: {presigned_data['object_key']}",
        )

        return PresignedUploadResponse(**presigned_data)
    except StorageValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err


@router.get(
    "/{doc_id}/download-url",
    status_code=status.HTTP_200_OK,
)
async def get_presigned_download_url(
    doc_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str | int]:
    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.get_by_id(doc_id=doc_id, org_id=current_user.org_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    if current_user.role == UserRole.CLIENT and doc.client_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot download documents assigned to another client",
        )

    # Document must be at least UPLOADED or APPROVED to download
    if doc.status not in (DocumentStatus.UPLOADED, DocumentStatus.APPROVED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot download document in state {doc.status.value}",
        )

    object_key = f"{doc.org_id}/{doc.client_id}/{doc.id}/document.pdf"
    download_data = storage_service.generate_presigned_download_url(
        object_key=object_key,
        filename=f"{doc.title}.pdf",
    )

    await audit_repo.log_event(
        org_id=current_user.org_id,
        document_id=doc.id,
        actor_id=current_user.user_id,
        action="DOCUMENT_DOWNLOAD_URL_ISSUED",
        details=f"Issued download token for {doc.title}",
    )

    return download_data


@router.get(
    "/{doc_id}/audit-trail",
    response_model=list[AuditEventResponse],
    status_code=status.HTTP_200_OK,
)
async def get_audit_trail(
    doc_id: str,
    current_user: AuthenticatedUser = Depends(
        RequireRoles([UserRole.CASE_MANAGER, UserRole.ORG_ADMIN])
    ),
    db: AsyncSession = Depends(get_db_session),
) -> list[AuditEventResponse]:
    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.get_by_id(doc_id=doc_id, org_id=current_user.org_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    events = await audit_repo.get_by_document(document_id=doc_id, org_id=current_user.org_id)
    return [AuditEventResponse.model_validate(event) for event in events]


@router.patch(
    "/{doc_id}/status",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_200_OK,
)
async def update_document_status(
    doc_id: str,
    payload: DocumentStatusUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> DocumentRequestModel:
    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.get_by_id(doc_id=doc_id, org_id=current_user.org_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    if current_user.role == UserRole.CLIENT and doc.client_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot update requests assigned to another client",
        )

    state_validator = DocumentRequest(
        id=doc.id,
        org_id=doc.org_id,
        client_id=doc.client_id,
        title=doc.title,
        status=doc.status,
    )

    try:
        state_validator.transition_to(payload.status, user_role=current_user.role.value)
    except DocumentRequestStateError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err

    old_status = doc.status.value
    updated = await repo.update_status(
        doc_id=doc.id,
        org_id=current_user.org_id,
        new_status=payload.status,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    await audit_repo.log_event(
        org_id=current_user.org_id,
        document_id=doc.id,
        actor_id=current_user.user_id,
        action="DOCUMENT_STATUS_TRANSITIONED",
        details=f"From {old_status} to {payload.status.value}",
    )

    return updated