"""Continuous-learning feedback endpoints."""

from fastapi import APIRouter, Body, Header, Request

from backend.dependencies import limiter, require_authenticated_uid
from backend.models import (
    LearningFeedbackRequest,
    LearningFeedbackResponse,
    LearningStatusResponse,
)

router = APIRouter(prefix="/learning")


@router.post("/feedback", response_model=LearningFeedbackResponse)
@limiter.limit("30/minute")
def queue_learning_feedback(
    request: Request,
    request_body: LearningFeedbackRequest = Body(...),
    authorization: str | None = Header(default=None),
) -> LearningFeedbackResponse:
    from backend.main import mailbox_store, telemetry

    uid = require_authenticated_uid(mailbox_store, authorization)
    telemetry.increment("learning.feedback.requests")
    queued_at = mailbox_store.save_learning_feedback(uid, request_body.model_dump())

    if mailbox_store.enabled:
        telemetry.increment("learning.feedback.stored")
    else:
        telemetry.increment("learning.feedback.disabled")

    return LearningFeedbackResponse(
        status="queued",
        queued_at=queued_at or "",
        continuous_learning_enabled=mailbox_store.enabled,
    )


@router.get("/status", response_model=LearningStatusResponse)
@limiter.limit("20/minute")
def get_learning_status(
    request: Request,
    authorization: str | None = Header(default=None),
) -> LearningStatusResponse:
    from backend.main import mailbox_store

    uid = require_authenticated_uid(mailbox_store, authorization)
    return LearningStatusResponse.model_validate(mailbox_store.get_learning_status(uid))
