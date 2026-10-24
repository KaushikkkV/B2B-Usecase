import pytest
from httpx import ASGITransport, AsyncClient

from app.core.database import AsyncSessionLocal, init_db
from app.core.security import create_access_token
from app.main import app
from app.models.document import DocumentStatus
from app.models.sql_document import SQLDocument


@pytest.mark.integration
async def test_end_to_end_encrypted_upload_and_decrypted_download(tmp_path, monkeypatch):
    await init_db()
    org_id = "org-crypto-e2e"
    user_id = "user-analyst-01"

    # Set up auth tokens
    token = create_access_token(
        data={"sub": user_id, "org_id": org_id, "role": "CASE_MANAGER"}
    )
    headers = {"Authorization": f"Bearer {token}"}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create a Document Request
        create_res = await client.post(
            "/api/v1/document-requests",
            json={"client_id": "client-cust-01", "title": "Confidential Tax Return"},
            headers=headers,
        )
        assert create_res.status_code == 201
        doc_id = create_res.json()["id"]

        # 2. Upload file payload (simulating multipart encrypted upload pipeline)
        plaintext_content = b"%PDF-1.4 Secret B2B corporate balance sheet."
        upload_res = await client.post(
            f"/api/v1/documents/{doc_id}/upload-direct",
            files={"file": ("balance_sheet.pdf", plaintext_content, "application/pdf")},
            headers=headers,
        )
        assert upload_res.status_code == 200

        # Verify DB metadata contains cryptographic envelope materials
        async with AsyncSessionLocal() as session:
            doc_record = await session.get(SQLDocument, doc_id)
            assert doc_record is not None
            assert doc_record.status == DocumentStatus.UPLOADED
            assert doc_record.wrapped_dek is not None
            assert doc_record.encryption_nonce is not None
            assert doc_record.auth_tag is not None

        # 3. Transition status to APPROVED to allow download
        patch_res = await client.patch(
            f"/api/v1/document-requests/{doc_id}/status",
            json={"status": "APPROVED"},
            headers=headers,
        )
        assert patch_res.status_code == 200

        # 4. Download file - verify transparent on-the-fly decryption
        download_res = await client.get(
            f"/api/v1/documents/{doc_id}/download-decrypted",
            headers=headers,
        )
        assert download_res.status_code == 200
        assert download_res.content == plaintext_content
        assert "attachment" in download_res.headers.get("content-disposition", "")