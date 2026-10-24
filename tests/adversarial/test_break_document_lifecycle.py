import pytest
from httpx import ASGITransport, AsyncClient

from app.core.security import create_access_token
from app.main import app


@pytest.mark.adversarial
async def test_exploit_cross_tenant_document_state_tampering():
    """
    ATTACK: Org A creates a document request.
    An attacker who is a CASE_MANAGER in Org B attempts to approve or reject Org A's document.
    Must return 404 Not Found (or 403) to prevent information disclosure.
    """
    # 1. Org A creates document
    token_org_a = create_access_token({
        "sub": "cm-org-a",
        "org_id": "org-victim-aaa",
        "role": "CASE_MANAGER",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Confidential Audit", "client_id": "client-a"},
            headers={"Authorization": f"Bearer {token_org_a}"},
        )
        doc_id = res.json()["id"]

        # 2. Org B Case Manager attempts to manipulate Org A's document
        token_org_b = create_access_token({
            "sub": "cm-org-b",
            "org_id": "org-attacker-bbb",
            "role": "CASE_MANAGER",
        })
        patch_res = await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "APPROVED"},
            headers={"Authorization": f"Bearer {token_org_b}"},
        )

    assert patch_res.status_code == 404, (
        f"BREACH: Cross-tenant document tampering permitted! Got status {patch_res.status_code}"
    )


@pytest.mark.adversarial
async def test_exploit_client_to_client_idor_same_org():
    """
    ATTACK: Within Org A, Client 1 is assigned Document 1.
    Client 2 (also in Org A) attempts to upload or transition Document 1.
    Must return 403 Forbidden.
    """
    cm_token = create_access_token({
        "sub": "cm-org-a",
        "org_id": "org-shared-aaa",
        "role": "CASE_MANAGER",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Client 1 Taxes", "client_id": "client-user-1"},
            headers={"Authorization": f"Bearer {cm_token}"},
        )
        doc_id = res.json()["id"]

        # Client 2 attempts to transition Client 1's request
        token_client_2 = create_access_token({
            "sub": "client-user-2",
            "org_id": "org-shared-aaa",
            "role": "CLIENT",
        })
        patch_res = await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "UPLOADED"},
            headers={"Authorization": f"Bearer {token_client_2}"},
        )

    assert patch_res.status_code == 403, (
        f"BREACH: Horizontal privilege escalation allowed between clients! Got {patch_res.status_code}"
    )


@pytest.mark.adversarial
async def test_exploit_terminal_approved_state_tampering():
    """
    ATTACK: A document is in APPROVED state.
    Even an ORG_ADMIN cannot alter its status back to PENDING or REJECTED.
    Must return 400 Bad Request.
    """
    admin_token = create_access_token({
        "sub": "admin-1",
        "org_id": "org-immutable-1",
        "role": "ORG_ADMIN",
    })
    client_token = create_access_token({
        "sub": "client-1",
        "org_id": "org-immutable-1",
        "role": "CLIENT",
    })

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Immutable Contract", "client_id": "client-1"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        doc_id = res.json()["id"]

        # PENDING -> UPLOADED
        await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "UPLOADED"},
            headers={"Authorization": f"Bearer {client_token}"},
        )

        # UPLOADED -> APPROVED
        await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "APPROVED"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        # ATTACK: Try to transition APPROVED -> REJECTED
        tamper_res = await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "REJECTED"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert tamper_res.status_code == 400
    assert "Invalid transition" in tamper_res.json()["detail"]


@pytest.mark.adversarial
async def test_exploit_invalid_enum_status_payload():
    """
    ATTACK: Send invalid status payloads (arbitrary strings or SQL injections).
    Must fail at Pydantic validation (422), never an unhandled 500.
    """
    admin_token = create_access_token({
        "sub": "admin-1",
        "org_id": "org-val-1",
        "role": "ORG_ADMIN",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.patch(
            "/api/v1/document-requests/doc-xyz/status",
            json={"status": "NOT_A_REAL_STATUS"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    assert res.status_code == 422