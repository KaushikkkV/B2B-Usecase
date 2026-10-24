import pytest
from app.core.database import get_db_session, init_db
from app.models.document import DocumentStatus
from app.repositories.sql_document import SQLDocumentRepository


@pytest.mark.adversarial
async def test_exploit_sql_injection_in_tenant_lookup():
    """
    ATTACK: Verify that parameterized queries block SQL injection payloads in org_id.
    """
    await init_db()
    async for session in get_db_session():
        repo = SQLDocumentRepository(session)
        created = await repo.create(
            org_id="org-sql-target",
            client_id="client-target",
            title="Secret Financials",
        )

        # Injection payload trying to match any record
        injected = await repo.get_by_id(
            doc_id=created.id,
            org_id="' OR '1'='1",
        )
        assert injected is None

        # Verify legitimate lookup still functions
        valid = await repo.get_by_id(
            doc_id=created.id,
            org_id="org-sql-target",
        )
        assert valid is not None
        assert valid.status == DocumentStatus.PENDING
        break