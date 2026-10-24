
from app.models.document import DocumentRequest


class DocumentRepository:
    def __init__(self) -> None:
        self._store: dict[str, DocumentRequest] = {}

    def save(self, doc: DocumentRequest) -> DocumentRequest:
        self._store[doc.id] = doc
        return doc

    def get_by_id(self, doc_id: str) -> DocumentRequest | None:
        return self._store.get(doc_id)


# Global repository instance
doc_repo = DocumentRepository()