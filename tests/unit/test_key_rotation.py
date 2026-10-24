import pytest

from app.core.crypto import CryptoVaultService, EncryptionError


def test_zero_plaintext_dek_rewrap_under_new_master_key():
    old_key = "old-master-secret-key-32bytes-v1!!"
    new_key = "new-master-secret-key-32bytes-v2!!"
    org_id = "org-enterprise-sec-44"
    plaintext_data = b"Confidential internal strategic memo."

    old_vault = CryptoVaultService(master_key=old_key)
    new_vault = CryptoVaultService(master_key=new_key)

    # 1. Document encrypted under old key
    ciphertext, old_wrapped_dek, nonce, tag = old_vault.encrypt_document(
        org_id=org_id,
        plaintext=plaintext_data,
    )

    # 2. Perform zero-plaintext re-wrap
    new_wrapped_dek = old_vault.rewrap_dek(
        org_id=org_id,
        wrapped_dek=old_wrapped_dek,
        new_master_key=new_key,
    )

    assert new_wrapped_dek != old_wrapped_dek

    # 3. Old vault must fail to decrypt with new wrapped DEK
    with pytest.raises(EncryptionError):
        old_vault.decrypt_document(
            org_id=org_id,
            ciphertext=ciphertext,
            wrapped_dek=new_wrapped_dek,
            nonce=nonce,
            tag=tag,
        )

    # 4. New vault must successfully decrypt untouched ciphertext using re-wrapped DEK
    decrypted = new_vault.decrypt_document(
        org_id=org_id,
        ciphertext=ciphertext,
        wrapped_dek=new_wrapped_dek,
        nonce=nonce,
        tag=tag,
    )
    assert decrypted == plaintext_data