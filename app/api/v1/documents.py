from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Response, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequireRoles, get_current_user
from app.core.crypto import CryptoVaultService, EncryptionError
from app.core.database import get_db_session
from app.core.rate_limit import rate_limiter
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

router = APIRouter(prefix="/api/v1", tags=["Documents"])
crypto_vault = CryptoVaultService()
STORAGE_DIR = Path("./.vault_storage")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


@router.get(
    "/documents",
    status_code=status.HTTP_200_OK,
)
async def list_documents(
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, list[DocumentRequestResponse] | str]:
    await rate_limiter.check_rate_limit(current_user.org_id)
    repo = SQLDocumentRepository(db)
    docs = await repo.list_by_org(org_id=current_user.org_id)
    if current_user.role == UserRole.CLIENT:
        docs = [d for d in docs if d.client_id == current_user.user_id]
    return {
        "user_id": current_user.user_id,
        "org_id": current_user.org_id,
        "documents": [DocumentRequestResponse.model_validate(d) for d in docs],
    }


@router.get(
    "/organization/settings",
    status_code=status.HTTP_200_OK,
)
async def get_organization_settings(
    current_user: AuthenticatedUser = Depends(RequireRoles([UserRole.ORG_ADMIN])),
) -> dict[str, str]:
    return {"org_id": current_user.org_id, "encryption_standard": "AES-256-GCM"}


@router.post(
    "/documents",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_201_CREATED,
)
@router.post(
    "/document-requests",
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
    await rate_limiter.check_rate_limit(current_user.org_id)
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
    "/documents/{doc_id}/upload-url",
    response_model=PresignedUploadResponse,
    status_code=status.HTTP_200_OK,
)
@router.post(
    "/document-requests/{doc_id}/upload-url",
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


@router.post(
    "/documents/{doc_id}/upload-direct",
    status_code=status.HTTP_200_OK,
)
async def upload_direct_encrypted_document(
    doc_id: str,
    file: UploadFile,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, str]:
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
            detail="Cannot upload documents assigned to another client",
        )

    raw_bytes = await file.read()
    if len(raw_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File cannot be empty",
        )

    ciphertext, wrapped_dek, nonce, tag = crypto_vault.encrypt_document(
        org_id=doc.org_id,
        plaintext=raw_bytes,
    )

    storage_filename = f"{doc.org_id}_{doc.id}.enc"
    storage_path = STORAGE_DIR / storage_filename
    storage_path.write_bytes(ciphertext)

    doc.file_name = file.filename
    doc.file_size_bytes = len(raw_bytes)
    doc.mime_type = file.content_type
    doc.storage_key = str(storage_path)
    doc.status = DocumentStatus.UPLOADED
    doc.wrapped_dek = wrapped_dek
    doc.encryption_nonce = nonce
    doc.auth_tag = tag

    await db.commit()
    await db.refresh(doc)

    await audit_repo.log_event(
        org_id=current_user.org_id,
        document_id=doc.id,
        actor_id=current_user.user_id,
        action="DOCUMENT_ENCRYPTED_AND_UPLOADED",
        details=f"Ciphertext size: {len(ciphertext)} bytes",
    )

    return {"status": "success", "document_id": doc.id}


@router.get(
    "/documents/{doc_id}/download-decrypted",
    status_code=status.HTTP_200_OK,
)
async def download_decrypted_document(
    doc_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> Response:
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

    if doc.is_infected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: file is quarantined as malware",
        )

    if doc.status != DocumentStatus.APPROVED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot download unapproved document in state {doc.status.value}",
        )

    if not (doc.wrapped_dek and doc.encryption_nonce and doc.auth_tag and doc.storage_key):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document cryptographic materials are missing or corrupted",
        )

    file_path = Path(doc.storage_key)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encrypted storage object missing",
        )

    ciphertext = file_path.read_bytes()

    try:
        decrypted = crypto_vault.decrypt_document(
            org_id=doc.org_id,
            ciphertext=ciphertext,
            wrapped_dek=doc.wrapped_dek,
            nonce=doc.encryption_nonce,
            tag=doc.auth_tag,
        )
    except EncryptionError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cryptographic verification failed: document tampered or invalid key",
        ) from exc

    await audit_repo.log_event(
        org_id=current_user.org_id,
        document_id=doc.id,
        actor_id=current_user.user_id,
        action="DOCUMENT_DECRYPTED_AND_DOWNLOADED",
        details=f"Document title: {doc.title}",
    )

    download_name = doc.file_name or f"{doc.title}.pdf"
    return Response(
        content=decrypted,
        media_type=doc.mime_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get(
    "/documents/{doc_id}/download-url",
    status_code=status.HTTP_200_OK,
)
@router.get(
    "/document-requests/{doc_id}/download-url",
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
    "/documents/{doc_id}/audit-trail",
    response_model=list[AuditEventResponse],
    status_code=status.HTTP_200_OK,
)
@router.get(
    "/document-requests/{doc_id}/audit-trail",
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
    "/documents/{doc_id}/status",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_200_OK,
)
@router.patch(
    "/document-requests/{doc_id}/status",
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