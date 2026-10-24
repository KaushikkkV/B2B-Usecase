from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import RequireRoles
from app.core.database import get_db_session
from app.repositories.audit import AuditRepository
from app.schemas.admin import KeyRotationRequest, KeyRotationResponse
from app.schemas.auth import AuthenticatedUser, UserRole
from app.services.key_rotation import KeyRotationService

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


@router.post(
    "/keys/rotate",
    response_model=KeyRotationResponse,
    status_code=status.HTTP_200_OK,
)
async def rotate_encryption_keys(
    payload: KeyRotationRequest,
    current_user: AuthenticatedUser = Depends(RequireRoles([UserRole.ORG_ADMIN])),
    db: AsyncSession = Depends(get_db_session),
) -> KeyRotationResponse:
    audit_repo = AuditRepository(db)

    try:
        service = KeyRotationService(
            old_master_key=payload.old_master_key,
            new_master_key=payload.new_master_key,
            target_version=payload.target_version,
        )
        migrated_count = await service.rotate_tenant_documents(
            session=db,
            org_id=current_user.org_id,
        )

        await audit_repo.log_event(
            org_id=current_user.org_id,
            document_id=None,
            actor_id=current_user.user_id,
            action="TENANT_KEY_ROTATION_COMPLETED",
            details=f"Target Version: {payload.target_version}, Migrated: {migrated_count}",
        )

        return KeyRotationResponse(
            status="completed",
            migrated_count=migrated_count,
            target_version=payload.target_version,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key rotation failed: {exc}",
        ) from exc