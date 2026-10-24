import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import create_access_token
from app.main import app


@pytest.mark.integration
async def test_case_manager_can_create_document_request():
    token = create_access_token({
        "sub": "user-cm-1",
        "org_id": "org-alpha-100",
        "role": "CASE_MANAGER",
    })

    payload = {
        "title": "2025 W-2 Form",
        "client_id": "client-user-9",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/document-requests",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "2025 W-2 Form"
    assert data["status"] == "PENDING"
    assert data["org_id"] == "org-alpha-100"
    assert "id" in data


@pytest.mark.integration
async def test_client_cannot_create_document_request():
    token = create_access_token({
        "sub": "client-user-9",
        "org_id": "org-alpha-100",
        "role": "CLIENT",
    })

    payload = {
        "title": "Unauthorized Request",
        "client_id": "client-user-9",
    }

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/document-requests",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 403


@pytest.mark.integration
async def test_client_can_mark_document_uploaded():
    # 1. Create as CASE_MANAGER
    cm_token = create_access_token({
        "sub": "user-cm-1",
        "org_id": "org-alpha-100",
        "role": "CASE_MANAGER",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Passport", "client_id": "client-user-9"},
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        doc_id = res.json()["id"]

        # 2. Transition to UPLOADED as CLIENT
        client_token = create_access_token({
            "sub": "client-user-9",
            "org_id": "org-alpha-100",
            "role": "CLIENT",
        })
        patch_res = await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "UPLOADED"},
            headers={"Authorization": f"Bearer {client_token}"},
        )

    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "UPLOADED"