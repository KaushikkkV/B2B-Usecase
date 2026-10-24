from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.sql_document import SQLDocument, DocumentStatus


class SQLDocumentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        org_id: str,
        client_id: str,
        title: str,
    ) -> SQLDocument:
        doc = SQLDocument(
            org_id=org_id,
            client_id=client_id,
            title=title,
            status=DocumentStatus.PENDING,
        )
        self.session.add(doc)
        await self.session.commit()
        await self.session.refresh(doc)
        return doc

    async def get_by_id(self, doc_id: str, org_id: str) -> SQLDocument | None:
        stmt = select(SQLDocument).where(
            SQLDocument.id == doc_id,
            SQLDocument.org_id == org_id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_id_system(self, doc_id: str) -> SQLDocument | None:
        stmt = select(SQLDocument).where(SQLDocument.id == doc_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(
        self,
        doc_id: str,
        org_id: str,
        new_status: DocumentStatus,
    ) -> SQLDocument | None:
        doc = await self.get_by_id(doc_id=doc_id, org_id=org_id)
        if not doc:
            return None
        doc.status = new_status
        await self.session.commit()
        await self.session.refresh(doc)
        return doc

    async def list_by_org(self, org_id: str) -> list[SQLDocument]:
        stmt = select(SQLDocument).where(SQLDocument.org_id == org_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())