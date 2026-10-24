import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import create_access_token
from app.main import app


@pytest.mark.integration
async def test_protected_route_rejects_missing_token():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/documents")

    assert response.status_code == 401
    assert "detail" in response.json()


@pytest.mark.integration
async def test_case_manager_can_access_document_workspace():
    token = create_access_token(
        {"sub": "user-cm-1", "org_id": "org-alpha-100", "role": "CASE_MANAGER"}
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/documents", headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["org_id"] == "org-alpha-100"
    assert data["user_id"] == "user-cm-1"


@pytest.mark.integration
async def test_client_role_forbidden_from_admin_management_route():
    token = create_access_token(
        {"sub": "client-user-9", "org_id": "org-alpha-100", "role": "CLIENT"}
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(
            "/api/v1/organization/settings", headers={"Authorization": f"Bearer {token}"}
        )

    assert response.status_code == 403
