from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEventModel


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def log_event(
        self,
        org_id: str,
        document_id: str | None,
        actor_id: str,
        action: str,
        details: str,
    ) -> AuditEventModel:
        event = AuditEventModel(
            org_id=org_id,
            document_id=document_id,
            actor_id=actor_id,
            action=action,
            details=details,
        )
        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)
        return event

    async def get_by_document(self, document_id: str, org_id: str) -> list[AuditEventModel]:
        stmt = (
            select(AuditEventModel)
            .where(
                AuditEventModel.document_id == document_id,
                AuditEventModel.org_id == org_id,
            )
            .order_by(AuditEventModel.timestamp.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())