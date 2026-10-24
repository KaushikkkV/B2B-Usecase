import pytest

from app.core.storage import S3StorageService, StorageValidationError


@pytest.mark.unit
def test_generate_presigned_upload_url_builds_tenant_isolated_key():
    service = S3StorageService(bucket_name="vault-documents")
    upload_data = service.generate_presigned_upload_url(
        org_id="org-alpha-100",
        client_id="client-42",
        document_id="doc-999",
        filename="tax_return.pdf",
        content_type="application/pdf",
        file_size_bytes=1024 * 1024,  # 1 MB
    )

    assert "url" in upload_data
    assert upload_data["object_key"] == "org-alpha-100/client-42/doc-999/tax_return.pdf"
    assert upload_data["expires_in"] == 900


@pytest.mark.unit
def test_reject_forbidden_file_extensions_and_mimetypes():
    service = S3StorageService(bucket_name="vault-documents")

    # Reject executable scripts
    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-alpha-100",
            client_id="client-42",
            document_id="doc-999",
            filename="malicious_script.sh",
            content_type="application/x-sh",
            file_size_bytes=512,
        )


@pytest.mark.unit
def test_reject_oversized_file_allocations():
    service = S3StorageService(bucket_name="vault-documents")

    # 30 MB (limit is 25 MB)
    oversized = 30 * 1024 * 1024
    with pytest.raises(StorageValidationError):
        service.generate_presigned_upload_url(
            org_id="org-alpha-100",
            client_id="client-42",
            document_id="doc-999",
            filename="huge_file.pdf",
            content_type="application/pdf",
            file_size_bytes=oversized,
        )