import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Enum, Index, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.models.document import DocumentStatus


class SQLDocument(Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus),
        default=DocumentStatus.PENDING,
        nullable=False,
    )
    is_infected: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Envelope Encryption Artifacts (AES-256-GCM)
    wrapped_dek: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    encryption_nonce: Mapped[bytes | None] = mapped_column(LargeBinary(12), nullable=True)
    auth_tag: Mapped[bytes | None] = mapped_column(LargeBinary(16), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_documents_org_id_id", "org_id", "id"),
        Index("ix_documents_org_id_client_id", "org_id", "client_id"),
    )


# Alias for backward-compatibility with repositories and API endpoints
DocumentRequestModel = SQLDocument