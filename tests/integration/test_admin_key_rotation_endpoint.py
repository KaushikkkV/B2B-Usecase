import pytest
from httpx import ASGITransport, AsyncClient

from app.core.crypto import CryptoVaultService
from app.core.database import AsyncSessionLocal, init_db
from app.core.security import create_access_token
from app.main import app
from app.models.document import DocumentStatus
from app.models.sql_document import SQLDocument


@pytest.mark.integration
async def test_admin_key_rotation_rbac_and_execution():
    await init_db()
    org_id = "org-admin-rotation"
    old_master_key = "b2b-vault-root-master-key-32bytes-long!"
    new_master_key = "admin-new-root-master-key-32bytes-v2!!"

    old_vault = CryptoVaultService(master_key=old_master_key)
    new_vault = CryptoVaultService(master_key=new_master_key)

    # 1. Seed document under old key (version 1)
    async with AsyncSessionLocal() as session:
        ciphertext, wrapped_dek, nonce, tag = old_vault.encrypt_document(
            org_id=org_id,
            plaintext=b"Critical organizational master vault backup.",
        )
        doc = SQLDocument(
            org_id=org_id,
            client_id="client-admin-1",
            title="Vault Backup",
            status=DocumentStatus.APPROVED,
            wrapped_dek=wrapped_dek,
            encryption_nonce=nonce,
            auth_tag=tag,
            key_version=1,
        )
        session.add(doc)
        await session.commit()
        await session.refresh(doc)
        target_doc_id = doc.id

    admin_token = create_access_token(
        data={"sub": "admin-01", "org_id": org_id, "role": "ORG_ADMIN"}
    )
    case_manager_token = create_access_token(
        data={"sub": "cm-01", "org_id": org_id, "role": "CASE_MANAGER"}
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 2. Case Manager forbidden (RBAC verification)
        cm_res = await client.post(
            "/api/v1/admin/keys/rotate",
            json={
                "old_master_key": old_master_key,
                "new_master_key": new_master_key,
                "target_version": 2,
            },
            headers={"Authorization": f"Bearer {case_manager_token}"},
        )
        assert cm_res.status_code == 403

        # 3. Org Admin initiates rotation
        admin_res = await client.post(
            "/api/v1/admin/keys/rotate",
            json={
                "old_master_key": old_master_key,
                "new_master_key": new_master_key,
                "target_version": 2,
            },
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert admin_res.status_code == 200
        res_data = admin_res.json()
        assert res_data["status"] == "completed"
        assert res_data["migrated_count"] == 1

    # 4. Verify record was rotated to key_version 2 and decrypts under new key
    async with AsyncSessionLocal() as session:
        refreshed = await session.get(SQLDocument, target_doc_id)
        assert refreshed is not None
        assert refreshed.key_version == 2

        decrypted = new_vault.decrypt_document(
            org_id=refreshed.org_id,
            ciphertext=ciphertext,
            wrapped_dek=refreshed.wrapped_dek,
            nonce=refreshed.encryption_nonce,
            tag=refreshed.auth_tag,
        )
        assert decrypted == b"Critical organizational master vault backup."