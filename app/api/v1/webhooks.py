import hashlib
import hmac
import json
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.models.document import DocumentStatus
from app.repositories.audit import AuditRepository
from app.repositories.sql_document import SQLDocumentRepository
from app.schemas.document import DocumentRequestResponse
from app.schemas.webhook import MalwareScanResult, MalwareScanWebhookPayload

router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

WEBHOOK_SECRET = os.getenv(
    "MALWARE_SCANNER_WEBHOOK_SECRET",
    "scanner-hmac-shared-secret-32bytes-min",
)


def verify_scanner_signature(payload_bytes: bytes, signature_header: str | None) -> None:
    if not signature_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing scanner signature",
        )

    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid scanner signature",
        )


@router.post(
    "/malware-scan",
    response_model=DocumentRequestResponse,
    status_code=status.HTTP_200_OK,
)
async def handle_malware_scan_webhook(
    request: Request,
    x_scanner_signature: str | None = Header(default=None, alias="X-Scanner-Signature"),
    db: AsyncSession = Depends(get_db_session),
) -> DocumentRequestResponse:
    raw_body = await request.body()
    verify_scanner_signature(raw_body, x_scanner_signature)

    try:
        data = json.loads(raw_body.decode("utf-8"))
        payload = MalwareScanWebhookPayload.model_validate(data)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Malformed webhook payload",
        ) from err

    repo = SQLDocumentRepository(db)
    audit_repo = AuditRepository(db)

    doc = await repo.get_by_id_system(payload.document_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document request not found",
        )

    if payload.scan_result == MalwareScanResult.INFECTED:
        doc.status = DocumentStatus.REJECTED
        await db.flush()
        await db.refresh(doc)

        await audit_repo.log_event(
            org_id=doc.org_id,
            document_id=doc.id,
            actor_id="system-malware-scanner",
            action="MALWARE_DETECTED_FILE_QUARANTINED",
            details=f"Threat: {payload.threat_name or 'Unknown'}. Document status forced to REJECTED.",
        )
    else:
        await audit_repo.log_event(
            org_id=doc.org_id,
            document_id=doc.id,
            actor_id="system-malware-scanner",
            action="MALWARE_SCAN_CLEAN",
            details="Automated scan verified no malicious payload.",
        )

    return DocumentRequestResponse.model_validate(doc)