import pytest

from app.core.crypto import CryptoVaultService
from app.core.database import AsyncSessionLocal, init_db
from app.models.document import DocumentStatus
from app.models.sql_document import SQLDocument
from app.services.key_rotation import KeyRotationService


@pytest.mark.integration
async def test_batch_re_encryption_migrates_all_legacy_records():
    await init_db()
    old_key = "batch-old-root-master-key-32bytes!"
    new_key = "batch-new-root-master-key-32bytes!"
    org_id = "org-batch-migration"

    old_vault = CryptoVaultService(master_key=old_key)
    new_vault = CryptoVaultService(master_key=new_key)

    created_ids = []
    # Seed 3 documents encrypted under old master key (version 1)
    async with AsyncSessionLocal() as session:
        for idx in range(3):
            payload = f"Sensitive contract contents #{idx}".encode()
            ciphertext, wrapped_dek, nonce, tag = old_vault.encrypt_document(
                org_id=org_id,
                plaintext=payload,
            )
            doc = SQLDocument(
                org_id=org_id,
                client_id="client-bulk-01",
                title=f"Contract #{idx}",
                status=DocumentStatus.APPROVED,
                wrapped_dek=wrapped_dek,
                encryption_nonce=nonce,
                auth_tag=tag,
                key_version=1,
            )
            session.add(doc)
            await session.commit()
            await session.refresh(doc)
            created_ids.append((doc.id, ciphertext, payload))

    # Execute batch migration to target_version=2
    rotation_service = KeyRotationService(
        old_master_key=old_key,
        new_master_key=new_key,
        target_version=2,
    )

    async with AsyncSessionLocal() as session:
        migrated_count = await rotation_service.rotate_tenant_documents(
            session=session,
            org_id=org_id,
            batch_size=2,
        )
        assert migrated_count == 3

    # Verify all records are now version 2 and decryptable with new key
    async with AsyncSessionLocal() as session:
        for doc_id, ciphertext, expected_payload in created_ids:
            doc = await session.get(SQLDocument, doc_id)
            assert doc is not None
            assert doc.key_version == 2

            decrypted = new_vault.decrypt_document(
                org_id=doc.org_id,
                ciphertext=ciphertext,
                wrapped_dek=doc.wrapped_dek,
                nonce=doc.encryption_nonce,
                tag=doc.auth_tag,
            )
            assert decrypted == expected_payload