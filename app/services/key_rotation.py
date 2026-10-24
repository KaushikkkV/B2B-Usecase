from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import CryptoVaultService
from app.models.sql_document import SQLDocument


class KeyRotationService:
    """
    Orchestrates zero-plaintext DEK re-wrapping across stored document records
    in controlled, paginated batches to prevent memory exhaustion and database lock contention.
    """

    def __init__(
        self,
        old_master_key: str | bytes,
        new_master_key: str | bytes,
        target_version: int,
    ) -> None:
        self.old_vault = CryptoVaultService(master_key=old_master_key)
        self.new_master_key = new_master_key
        self.target_version = target_version

    async def rotate_tenant_documents(
        self,
        session: AsyncSession,
        org_id: str,
        batch_size: int = 50,
    ) -> int:
        total_migrated = 0

        while True:
            stmt = (
                select(SQLDocument)
                .where(
                    SQLDocument.org_id == org_id,
                    SQLDocument.key_version < self.target_version,
                    SQLDocument.wrapped_dek.is_not(None),
                )
                .limit(batch_size)
            )
            result = await session.execute(stmt)
            batch = result.scalars().all()

            if not batch:
                break

            for doc in batch:
                if doc.wrapped_dek is None:
                    continue

                new_wrapped_dek = self.old_vault.rewrap_dek(
                    org_id=doc.org_id,
                    wrapped_dek=doc.wrapped_dek,
                    new_master_key=self.new_master_key,
                )

                doc.wrapped_dek = new_wrapped_dek
                doc.key_version = self.target_version
                total_migrated += 1

            await session.commit()

        return total_migrated