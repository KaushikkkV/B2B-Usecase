from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.document import DocumentStatus
from app.models.sql_document import DocumentRequestModel


class SQLDocumentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        org_id: str,
        client_id: str,
        title: str,
    ) -> DocumentRequestModel:
        doc = DocumentRequestModel(
            org_id=org_id,
            client_id=client_id,
            title=title,
            status=DocumentStatus.PENDING,
        )
        self.session.add(doc)
        await self.session.flush()
        await self.session.refresh(doc)
        return doc

    async def get_by_id(
        self,
        doc_id: str,
        org_id: str,
    ) -> DocumentRequestModel | None:
        """Tenant-scoped retrieval: always requires matching org_id."""
        query = select(DocumentRequestModel).where(
            DocumentRequestModel.id == doc_id,
            DocumentRequestModel.org_id == org_id,
        )
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_id_system(
        self,
        doc_id: str,
    ) -> DocumentRequestModel | None:
        """System-level retrieval for trusted internal workers and scanner webhooks."""
        query = select(DocumentRequestModel).where(DocumentRequestModel.id == doc_id)
        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def update_status(
        self,
        doc_id: str,
        org_id: str,
        new_status: DocumentStatus,
    ) -> DocumentRequestModel | None:
        doc = await self.get_by_id(doc_id, org_id)
        if not doc:
            return None
        doc.status = new_status
        await self.session.flush()
        await self.session.refresh(doc)
        return doc