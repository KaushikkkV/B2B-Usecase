import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EncryptionError(Exception):
    """Raised when encryption, decryption, or cryptographic integrity verification fails."""


class CryptoVaultService:
    """
    Zero-trust Envelope Encryption service implementing AES-256-GCM
    with per-tenant Key Encryption Key (KEK) derivation and ephemeral Data Encryption Keys (DEKs).
    """

    def __init__(self, master_key: str | bytes | None = None) -> None:
        raw_key: str | bytes = (
            master_key
            or os.getenv("VAULT_MASTER_KEY")
            or "b2b-vault-root-master-key-32bytes-long!"
        )

        if isinstance(raw_key, str):
            self.master_key: bytes = raw_key.encode("utf-8")
        else:
            self.master_key = raw_key

        if len(self.master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes (256 bits) for cryptographic security.")

    def _derive_tenant_kek(self, org_id: str) -> bytes:
        """Derive a deterministic, tenant-isolated 256-bit KEK using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"b2b-vault-tenant-kek-salt-v1",
            info=f"tenant-kek:{org_id}".encode(),
        )
        return hkdf.derive(self.master_key)

    def encrypt_document(
        self,
        org_id: str,
        plaintext: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Encrypts a document payload under a fresh DEK and wraps the DEK under the tenant's KEK.

        Returns:
            tuple[ciphertext, wrapped_dek, nonce, tag]
        """
        try:
            # 1. Generate an ephemeral 256-bit Data Encryption Key (DEK)
            dek = AESGCM.generate_key(bit_length=256)

            # 2. Encrypt plaintext payload with DEK using AES-256-GCM
            payload_nonce = os.urandom(12)
            aesgcm = AESGCM(dek)
            aad = f"vault-doc:{org_id}".encode()

            encrypted_with_tag = aesgcm.encrypt(payload_nonce, plaintext, aad)
            ciphertext = encrypted_with_tag[:-16]
            tag = encrypted_with_tag[-16:]

            # 3. Derive tenant KEK and wrap the ephemeral DEK
            tenant_kek = self._derive_tenant_kek(org_id)
            kek_gcm = AESGCM(tenant_kek)
            dek_nonce = os.urandom(12)
            wrapped_dek_with_tag = kek_gcm.encrypt(dek_nonce, dek, aad)
            wrapped_dek = dek_nonce + wrapped_dek_with_tag

            return ciphertext, wrapped_dek, payload_nonce, tag

        except Exception as exc:
            raise EncryptionError(f"Encryption failed: {exc}") from exc

    def decrypt_document(
        self,
        org_id: str,
        ciphertext: bytes,
        wrapped_dek: bytes,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """
        Unwraps the DEK using the tenant's KEK, verifies AEAD authentication tags,
        and decrypts the document ciphertext back to plaintext.
        """
        if len(wrapped_dek) < 28:
            raise EncryptionError("Invalid wrapped DEK structure")

        try:
            # 1. Derive tenant KEK and unwrap DEK
            tenant_kek = self._derive_tenant_kek(org_id)
            kek_gcm = AESGCM(tenant_kek)
            aad = f"vault-doc:{org_id}".encode()

            dek_nonce = wrapped_dek[:12]
            wrapped_payload = wrapped_dek[12:]
            dek = kek_gcm.decrypt(dek_nonce, wrapped_payload, aad)

            # 2. Decrypt document ciphertext using DEK
            aesgcm = AESGCM(dek)
            encrypted_with_tag = ciphertext + tag
            plaintext = aesgcm.decrypt(nonce, encrypted_with_tag, aad)

            return plaintext

        except (InvalidTag, InvalidSignature) as exc:
            raise EncryptionError("Cryptographic integrity verification failed. Data may be tampered.") from exc
        except Exception as exc:
            raise EncryptionError(f"Decryption failed: {exc}") from exc