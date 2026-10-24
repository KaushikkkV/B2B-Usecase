from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLogModel


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def log_event(
        self,
        org_id: str,
        document_id: str,
        actor_id: str,
        action: str,
        details: str = "",
    ) -> AuditLogModel:
        event = AuditLogModel(
            org_id=org_id,
            document_id=document_id,
            actor_id=actor_id,
            action=action,
            details=details,
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_by_document(
        self,
        document_id: str,
        org_id: str,
    ) -> Sequence[AuditLogModel]:
        stmt = (
            select(AuditLogModel)
            .where(
                AuditLogModel.document_id == document_id,
                AuditLogModel.org_id == org_id,
            )
            .order_by(AuditLogModel.created_at.asc())
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()