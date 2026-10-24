import os
import re
from typing import Any

import boto3
from botocore.config import Config


class StorageValidationError(Exception):
    """Raised when file parameters violate security constraints."""


SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


class S3StorageService:
    ALLOWED_CONTENT_TYPES: set[str] = {
        "application/pdf",
        "image/png",
        "image/jpeg",
    }
    ALLOWED_EXTENSIONS: set[str] = {
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
    }
    MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB limit
    DEFAULT_EXPIRY_SECONDS: int = 900  # 15 minutes

    def __init__(
        self,
        bucket_name: str = "vault-documents",
        region: str = "us-east-1",
        endpoint_url: str | None = None,
    ) -> None:
        self.bucket_name = bucket_name
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID", "local-dev-key")
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "local-dev-secret")

        self.client = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key,
            config=Config(signature_version="s3v4"),
        )

    def generate_presigned_upload_url(
        self,
        org_id: str,
        client_id: str,
        document_id: str,
        filename: str,
        content_type: str,
        file_size_bytes: int,
    ) -> dict[str, Any]:
        # 1. Filename sanitization: prevent path traversal attacks
        if (
            not filename
            or not SAFE_FILENAME_REGEX.match(filename)
            or ".." in filename
            or "/" in filename
            or "\\" in filename
        ):
            raise StorageValidationError(f"Invalid or unsafe filename '{filename}'")

        # 2. Extension validation: check terminal extension to defeat double extensions
        lower_name = filename.lower()
        _, ext = os.path.splitext(lower_name)
        if ext not in self.ALLOWED_EXTENSIONS:
            raise StorageValidationError(f"Disallowed terminal file extension '{ext}'")

        # 3. Validate content type
        if content_type not in self.ALLOWED_CONTENT_TYPES:
            raise StorageValidationError(
                f"Disallowed content type '{content_type}'. Must be one of {self.ALLOWED_CONTENT_TYPES}"
            )

        # 4. Validate file size allocation
        if file_size_bytes <= 0 or file_size_bytes > self.MAX_FILE_SIZE_BYTES:
            raise StorageValidationError(
                f"File size {file_size_bytes} bytes exceeds bounds (1 to {self.MAX_FILE_SIZE_BYTES} bytes)"
            )

        # 5. Deterministic multi-tenant path isolation
        object_key = f"{org_id}/{client_id}/{document_id}/{filename}"

        # 6. Generate Pre-Signed PUT URL
        url = self.client.generate_presigned_url(
            ClientMethod="put_object",
            Params={
                "Bucket": self.bucket_name,
                "Key": object_key,
                "ContentType": content_type,
            },
            ExpiresIn=self.DEFAULT_EXPIRY_SECONDS,
        )

        return {
            "url": url,
            "object_key": object_key,
            "expires_in": self.DEFAULT_EXPIRY_SECONDS,
        }


storage_service = S3StorageService()