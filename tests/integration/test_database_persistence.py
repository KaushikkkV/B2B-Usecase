import pytest

from app.core.database import get_db_session, init_db
from app.models.document import DocumentStatus
from app.repositories.sql_document import SQLDocumentRepository


@pytest.mark.integration
async def test_sql_document_repository_lifecycle():
    await init_db()

    async for session in get_db_session():
        repo = SQLDocumentRepository(session)
        created_doc = await repo.create(
            org_id="org-sql-test",
            client_id="client-sql-1",
            title="Tax Return 2026",
        )
        assert created_doc.id is not None
        assert created_doc.status == DocumentStatus.PENDING

        fetched_doc = await repo.get_by_id(
            doc_id=created_doc.id,
            org_id="org-sql-test",
        )
        assert fetched_doc is not None
        assert fetched_doc.title == "Tax Return 2026"

        cross_tenant_doc = await repo.get_by_id(
            doc_id=created_doc.id,
            org_id="org-different-tenant",
        )
        assert cross_tenant_doc is None

        updated_doc = await repo.update_status(
            doc_id=created_doc.id,
            org_id="org-sql-test",
            new_status=DocumentStatus.UPLOADED,
        )
        assert updated_doc is not None
        assert updated_doc.status == DocumentStatus.UPLOADED
        break