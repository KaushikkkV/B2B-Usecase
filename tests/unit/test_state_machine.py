import pytest

from app.models.document import DocumentRequest, DocumentRequestStateError, DocumentStatus


@pytest.mark.unit
def test_valid_state_transitions():
    doc = DocumentRequest(
        id="doc-1",
        org_id="org-1",
        client_id="client-1",
        title="2025 Tax Return",
        status=DocumentStatus.PENDING,
    )

    doc.transition_to(DocumentStatus.UPLOADED, user_role="CLIENT")
    assert doc.status == DocumentStatus.UPLOADED

    doc.transition_to(DocumentStatus.APPROVED, user_role="CASE_MANAGER")
    assert doc.status == DocumentStatus.APPROVED


@pytest.mark.unit
def test_client_cannot_approve_document():
    doc = DocumentRequest(
        id="doc-2",
        org_id="org-1",
        client_id="client-1",
        title="Passport Scan",
        status=DocumentStatus.UPLOADED,
    )

    with pytest.raises(DocumentRequestStateError):
        doc.transition_to(DocumentStatus.APPROVED, user_role="CLIENT")


@pytest.mark.unit
def test_cannot_skip_directly_from_pending_to_approved():
    doc = DocumentRequest(
        id="doc-3",
        org_id="org-1",
        client_id="client-1",
        title="Bank Statement",
        status=DocumentStatus.PENDING,
    )

    with pytest.raises(DocumentRequestStateError):
        doc.transition_to(DocumentStatus.APPROVED, user_role="CASE_MANAGER")


@pytest.mark.unit
def test_approved_document_is_terminal_and_immutable():
    doc = DocumentRequest(
        id="doc-4",
        org_id="org-1",
        client_id="client-1",
        title="Articles of Incorporation",
        status=DocumentStatus.APPROVED,
    )

    with pytest.raises(DocumentRequestStateError):
        doc.transition_to(DocumentStatus.REJECTED, user_role="CASE_MANAGER")

    with pytest.raises(DocumentRequestStateError):
        doc.transition_to(DocumentStatus.UPLOADED, user_role="CLIENT")