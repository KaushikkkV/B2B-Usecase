from fastapi import Depends, FastAPI, status

from app.api.deps import RequireRoles
from app.schemas.auth import AuthenticatedUser, UserRole

app = FastAPI(
    title="B2B Secure Document Vault",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)


@app.get("/healthz", status_code=status.HTTP_200_OK, tags=["Health"])
async def healthcheck() -> dict[str, str]:
    return {"status": "ok", "service": "b2b-document-vault"}


@app.get("/api/v1/documents", status_code=status.HTTP_200_OK, tags=["Documents"])
async def list_documents(
    current_user: AuthenticatedUser = Depends(
        RequireRoles([UserRole.ORG_ADMIN, UserRole.CASE_MANAGER, UserRole.CLIENT])
    ),
) -> dict[str, str]:
    return {
        "status": "success",
        "org_id": current_user.org_id,
        "user_id": current_user.user_id,
        "role": current_user.role.value,
    }


@app.get("/api/v1/organization/settings", status_code=status.HTTP_200_OK, tags=["Admin"])
async def organization_settings(
    current_user: AuthenticatedUser = Depends(RequireRoles([UserRole.ORG_ADMIN])),
) -> dict[str, str]:
    return {
        "status": "success",
        "org_id": current_user.org_id,
        "message": "Admin settings loaded",
    }
