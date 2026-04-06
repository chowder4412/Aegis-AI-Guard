"""Gmail mailbox session and scan endpoints."""

import logging

from fastapi import APIRouter, Body, Header, HTTPException, Request

from backend.dependencies import limiter, require_authenticated_uid
from backend.gmail_mailbox import GmailMailboxError
from backend.models import (
    GmailMailboxDeleteResponse,
    GmailMailboxScanRequest,
    GmailMailboxScanResponse,
    GmailMailboxSessionRequest,
    GmailMailboxSessionResponse,
)

logger = logging.getLogger("aegis.backend")

router = APIRouter(prefix="/mailboxes/gmail")


@router.post("/session", response_model=GmailMailboxSessionResponse)
@limiter.limit("20/minute")
def store_gmail_mailbox_session(
    request: Request,
    request_body: GmailMailboxSessionRequest = Body(...),
    authorization: str | None = Header(default=None),
) -> GmailMailboxSessionResponse:
    from backend.main import mailbox_store

    uid = require_authenticated_uid(mailbox_store, authorization)
    mailbox_store.save_gmail_oauth_session(
        uid,
        request_body.email,
        access_token=request_body.access_token,
        refresh_token=request_body.refresh_token,
        id_token=request_body.id_token,
        scope=request_body.scope,
        token_type=request_body.token_type,
        expires_in=request_body.expires_in,
        issued_at=request_body.issued_at,
    )
    return GmailMailboxSessionResponse(email=request_body.email.strip().lower(), status="stored")


@router.post("/scan", response_model=GmailMailboxScanResponse)
@limiter.limit("10/minute")
async def scan_gmail_mailbox(
    request: Request,
    request_body: GmailMailboxScanRequest = Body(...),
    authorization: str | None = Header(default=None),
) -> GmailMailboxScanResponse:
    from backend.main import gmail_mailbox_scanner, mailbox_store

    uid = require_authenticated_uid(mailbox_store, authorization)
    try:
        result = await gmail_mailbox_scanner.scan_mailbox(uid, request_body.email, request_body.limit)
    except GmailMailboxError as exc:
        mailbox_store.mark_gmail_scan_failure(uid, request_body.email, str(exc))
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        mailbox_store.mark_gmail_scan_failure(uid, request_body.email, "gmail mailbox scan failed")
        logger.exception("gmail_mailbox_scan_failed uid=%s email=%s", uid, request_body.email)
        raise HTTPException(status_code=500, detail="gmail mailbox scan failed") from exc

    return GmailMailboxScanResponse.model_validate(result)


@router.delete("/{email:path}", response_model=GmailMailboxDeleteResponse)
@limiter.limit("20/minute")
def delete_gmail_mailbox_session(
    email: str,
    request: Request,
    authorization: str | None = Header(default=None),
) -> GmailMailboxDeleteResponse:
    from backend.main import mailbox_store

    uid = require_authenticated_uid(mailbox_store, authorization)
    normalized_email = email.strip().lower()
    mailbox_store.delete_gmail_oauth_session(uid, normalized_email)
    return GmailMailboxDeleteResponse(email=normalized_email, status="deleted")
