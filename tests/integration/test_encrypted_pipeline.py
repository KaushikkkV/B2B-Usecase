import pytest

from app.core.crypto import CryptoVaultService
from app.core.database import AsyncSessionLocal, init_db
from app.models.document import DocumentStatus
from app.models.sql_document import SQLDocument


@pytest.mark.integration
async def test_envelope_encrypted_document_storage_and_recovery():
    await init_db()
    crypto = CryptoVaultService()
    org_id = "org-fintech-sec-01"
    raw_payload = b"%PDF-1.7 Confidential financial transaction ledger."

    # 1. Encrypt payload before persisting
    ciphertext, wrapped_dek, nonce, tag = crypto.encrypt_document(
        org_id=org_id,
        plaintext=raw_payload,
    )

    # 2. Persist document record with cryptographic artifacts
    async with AsyncSessionLocal() as session:
        doc = SQLDocument(
            org_id=org_id,
            client_id="client-cust-99",
            title="Q3 Audit Ledger",
            file_name="audit_ledger.pdf",
            file_size_bytes=len(ciphertext),
            storage_key=f"encrypted/{org_id}/client-cust-99/test-doc.enc",
            status=DocumentStatus.UPLOADED,
            wrapped_dek=wrapped_dek,
            encryption_nonce=nonce,
            auth_tag=tag,
        )
        session.add(doc)
        await session.commit()
        await session.refresh(doc)
        saved_id = doc.id

    # 3. Retrieve and decrypt using stored envelope metadata
    async with AsyncSessionLocal() as session:
        retrieved = await session.get(SQLDocument, saved_id)
        assert retrieved is not None
        assert retrieved.wrapped_dek is not None
        assert retrieved.encryption_nonce is not None
        assert retrieved.auth_tag is not None

        decrypted = crypto.decrypt_document(
            org_id=retrieved.org_id,
            ciphertext=ciphertext,
            wrapped_dek=retrieved.wrapped_dek,
            nonce=retrieved.encryption_nonce,
            tag=retrieved.auth_tag,
        )
        assert decrypted == raw_payload