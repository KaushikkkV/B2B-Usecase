import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SQLAuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    org_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_audit_org_id_timestamp", "org_id", "timestamp"),
        Index("ix_audit_document_id", "document_id"),
    )


AuditEventModel = SQLAuditEvent
AuditEvent = SQLAuditEvent