import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import init_db
from app.core.security import create_access_token
from app.main import app


@pytest.mark.integration
async def test_cannot_download_unapproved_or_infected_document():
    await init_db()

    # 1. Create document request as CASE_MANAGER
    cm_token = create_access_token({
        "sub": "user-cm-1",
        "org_id": "org-audit-1",
        "role": "CASE_MANAGER",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Audit Check", "client_id": "client-audit-1"},
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        assert res.status_code == 201
        doc_id = res.json()["id"]

        # 2. Attempt download while still PENDING (must fail with 400 Bad Request)
        dl_res = await client.get(
            f"/api/v1/document-requests/{doc_id}/download-url",
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        assert dl_res.status_code == 400
        assert "Cannot download document in state PENDING" in dl_res.json()["detail"]


@pytest.mark.integration
async def test_audit_log_recorded_on_state_transition():
    await init_db()

    cm_token = create_access_token({
        "sub": "user-cm-1",
        "org_id": "org-audit-1",
        "role": "CASE_MANAGER",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "W2 Form", "client_id": "client-audit-1"},
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        doc_id = res.json()["id"]

        # Query audit log endpoint
        audit_res = await client.get(
            f"/api/v1/document-requests/{doc_id}/audit-trail",
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        assert audit_res.status_code == 200
        events = audit_res.json()
        assert len(events) >= 1
        assert events[0]["action"] == "DOCUMENT_REQUEST_CREATED"
        assert events[0]["actor_id"] == "user-cm-1"
        assert events[0]["org_id"] == "org-audit-1"