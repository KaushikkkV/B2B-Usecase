import pytest

from app.core.crypto import CryptoVaultService, EncryptionError


def test_encrypt_decrypt_roundtrip_preserves_payload():
    service = CryptoVaultService(master_key="b2b-vault-root-master-key-32bytes-long!")
    payload = b"Confidential business document payload with sensitive financial audit data."

    encrypted_data, wrapped_dek, nonce, tag = service.encrypt_document(
        org_id="org-acme-101",
        plaintext=payload,
    )

    assert encrypted_data != payload
    assert len(nonce) == 12  # Standard 96-bit AES-GCM IV

    decrypted = service.decrypt_document(
        org_id="org-acme-101",
        ciphertext=encrypted_data,
        wrapped_dek=wrapped_dek,
        nonce=nonce,
        tag=tag,
    )
    assert decrypted == payload


def test_cross_tenant_key_isolation_fails_decryption():
    service = CryptoVaultService(master_key="b2b-vault-root-master-key-32bytes-long!")
    payload = b"Top secret corporate acquisition contract"

    encrypted_data, wrapped_dek, nonce, tag = service.encrypt_document(
        org_id="org-victim-001",
        plaintext=payload,
    )

    # Attempt decryption claiming to be a different organization
    with pytest.raises(EncryptionError):
        service.decrypt_document(
            org_id="org-attacker-999",
            ciphertext=encrypted_data,
            wrapped_dek=wrapped_dek,
            nonce=nonce,
            tag=tag,
        )


def test_tampered_ciphertext_fails_authentication_tag_check():
    service = CryptoVaultService(master_key="b2b-vault-root-master-key-32bytes-long!")
    payload = b"Pristine unmodified payload"

    encrypted_data, wrapped_dek, nonce, tag = service.encrypt_document(
        org_id="org-acme-101",
        plaintext=payload,
    )

    # Bit-flip ciphertext to simulate malicious tampering in storage
    tampered = bytearray(encrypted_data)
    tampered[0] ^= 0xFF

    with pytest.raises(EncryptionError):
        service.decrypt_document(
            org_id="org-acme-101",
            ciphertext=bytes(tampered),
            wrapped_dek=wrapped_dek,
            nonce=nonce,
            tag=tag,
        )