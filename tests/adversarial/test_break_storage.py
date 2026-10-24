import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import init_db
from app.core.security import create_access_token
from app.core.storage import S3StorageService, StorageValidationError
from app.main import app


@pytest.mark.adversarial
def test_exploit_path_traversal_filename_escape():
    """
    ATTACK: An attacker passes directory traversal patterns in the filename
    to break out of the /{org_id}/{client_id}/{document_id}/ prefix.
    """
    service = S3StorageService(bucket_name="vault-documents")

    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-victim",
            client_id="client-victim",
            document_id="doc-123",
            filename="../../system/danger.pdf",
            content_type="application/pdf",
            file_size_bytes=1024,
        )


@pytest.mark.adversarial
def test_exploit_double_extension_executable():
    """
    ATTACK: Attempting to upload an executable disguised with a double extension.
    """
    service = S3StorageService(bucket_name="vault-documents")

    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-1",
            client_id="client-1",
            document_id="doc-1",
            filename="invoice.pdf.exe",
            content_type="application/pdf",
            file_size_bytes=1024,
        )


@pytest.mark.adversarial
async def test_exploit_cross_tenant_presigned_url_theft():
    """
    ATTACK: Org A creates a document request.
    Client in Org B attempts to request an upload URL for Org A's document.
    Must return 404 Not Found to prevent data exposure.
    """
    await init_db()

    # 1. Org A creates doc
    cm_a_token = create_access_token({
        "sub": "cm-org-a",
        "org_id": "org-aaa",
        "role": "CASE_MANAGER",
    })
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/api/v1/document-requests",
            json={"title": "Audit Doc", "client_id": "client-a"},
            headers={"Authorization": f"Bearer {cm_a_token}"},
        )
        doc_id = res.json()["id"]

        # 2. Org B Client attempts to generate upload URL for Org A's document
        client_b_token = create_access_token({
            "sub": "client-b",
            "org_id": "org-bbb",
            "role": "CLIENT",
        })
        attack_res = await client.post(
            f"/api/v1/document-requests/{doc_id}/upload-url",
            json={
                "filename": "poison.pdf",
                "content_type": "application/pdf",
                "file_size_bytes": 1024,
            },
            headers={"Authorization": f"Bearer {client_b_token}"},
        )

    assert attack_res.status_code == 404


@pytest.mark.adversarial
def test_exploit_negative_or_zero_byte_allocation():
    """
    ATTACK: Submitting 0 or negative byte sizes to trigger logic bugs in allocation.
    """
    service = S3StorageService(bucket_name="vault-documents")

    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-1",
            client_id="client-1",
            document_id="doc-1",
            filename="valid.pdf",
            content_type="application/pdf",
            file_size_bytes=0,
        )

    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-1",
            client_id="client-1",
            document_id="doc-1",
            filename="valid.pdf",
            content_type="application/pdf",
            file_size_bytes=-1024,
        )