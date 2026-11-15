"""Link sandbox inspection and detonation endpoints."""

import logging

from fastapi import APIRouter, Body, Header, HTTPException, Request

from backend.dependencies import limiter, verify_sandbox_access
from backend.link_sandbox import LinkSandboxError
from backend.models import (
    DetonationJobCreateResponse,
    DetonationJobResponse,
    DetonationRequest,
    DetonationResultResponse,
    LinkInspectionJobCreateResponse,
    LinkInspectionJobResponse,
    LinkInspectionRequest,
    LinkInspectionResponse,
)

logger = logging.getLogger("aegis.backend")

router = APIRouter(prefix="/sandbox")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def to_link_inspection_response(
    result,
    *,
    detonation_job_id: str | None = None,
    detonation_status: str | None = None,
) -> LinkInspectionResponse:
    return LinkInspectionResponse(
        analysis_id=result.analysis_id,
        healthy=result.healthy,
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        reasons=result.reasons,
        final_url=result.final_url,
        reputation_flagged=result.reputation_flagged,
        credential_form_detected=result.credential_form_detected,
        credential_submission_succeeded=result.credential_submission_succeeded,
        dangerous_download_detected=result.dangerous_download_detected,
        detonation_job_id=detonation_job_id,
        detonation_status=detonation_status,  # type: ignore[arg-type]
    )


def _should_escalate_to_detonation(result) -> bool:
    if result.dangerous_download_detected:
        return True
    if result.credential_submission_succeeded:
        return True
    return result.verdict in {"scam", "suspicious"} and result.risk_score >= 60


async def _auto_escalate_detonation(url: str, source_email: str | None = None) -> tuple[str | None, str | None]:
    from backend.main import detonation_manager, telemetry

    if not detonation_manager.enabled:
        return (None, None)
    job = await detonation_manager.submit(url, source_email=source_email)
    telemetry.increment("detonation.auto_submit")
    return (job.id, job.status)


def to_detonation_job_response(job) -> DetonationJobResponse:
    result = None
    if job.result:
        result = DetonationResultResponse(
            verdict=job.result.verdict,  # type: ignore[arg-type]
            risk_score=job.result.risk_score,
            confidence=job.result.confidence,
            summary=job.result.summary,
        )
    return DetonationJobResponse(
        job_id=job.id,
        status=job.status,  # type: ignore[arg-type]
        created_at=job.created_at,
        finished_at=job.finished_at,
        result=result,
        error=job.error,
    )


# ---------------------------------------------------------------------------
# Link inspection endpoints
# ---------------------------------------------------------------------------

@router.post("/inspect-link", response_model=LinkInspectionResponse)
@limiter.limit("20/minute")
async def inspect_link(
    request: Request,
    request_body: LinkInspectionRequest = Body(...),
    x_sandbox_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> LinkInspectionResponse:
    from backend.main import link_sandbox, mailbox_store, settings, telemetry

    verify_sandbox_access(mailbox_store, settings.link_sandbox_api_key, x_sandbox_key, authorization)
    telemetry.increment("sandbox.sync.requests")

    try:
        result = await link_sandbox.inspect(request_body.url)
    except LinkSandboxError as exc:
        telemetry.increment("sandbox.sync.blocked")
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        telemetry.increment("sandbox.sync.failures")
        logger.exception("sandbox_inspection_failed url=%s", request_body.url)
        raise HTTPException(status_code=500, detail="link inspection failed") from exc

    telemetry.increment("sandbox.sync.success")

    detonation_job_id: str | None = None
    detonation_status: str | None = None
    if _should_escalate_to_detonation(result):
        detonation_job_id, detonation_status = await _auto_escalate_detonation(request_body.url, request_body.source_email)

    return to_link_inspection_response(
        result,
        detonation_job_id=detonation_job_id,
        detonation_status=detonation_status,
    )


@router.post("/inspect-link/async", response_model=LinkInspectionJobCreateResponse)
@limiter.limit("20/minute")
async def inspect_link_async(
    request: Request,
    request_body: LinkInspectionRequest = Body(...),
    x_sandbox_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> LinkInspectionJobCreateResponse:
    from backend.main import mailbox_store, sandbox_queue, settings, telemetry

    verify_sandbox_access(mailbox_store, settings.link_sandbox_api_key, x_sandbox_key, authorization)
    telemetry.increment("sandbox.async.requests")
    job = await sandbox_queue.submit(request_body.url, request_body.source_email)
    return LinkInspectionJobCreateResponse(job_id=job.id, status="queued")


@router.get("/inspect-link/jobs/{job_id}", response_model=LinkInspectionJobResponse)
@limiter.limit("60/minute")
async def get_link_inspection_job(
    job_id: str,
    request: Request,
    x_sandbox_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> LinkInspectionJobResponse:
    from backend.main import mailbox_store, sandbox_queue, settings

    verify_sandbox_access(mailbox_store, settings.link_sandbox_api_key, x_sandbox_key, authorization)
    job = sandbox_queue.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="sandbox job not found")

    detonation_job_id: str | None = getattr(job, "detonation_job_id", None)
    detonation_status: str | None = getattr(job, "detonation_status", None)
    if (
        job.status == "completed"
        and job.result is not None
        and _should_escalate_to_detonation(job.result)
        and not detonation_job_id
    ):
        detonation_job_id, detonation_status = await _auto_escalate_detonation(job.url, job.source_email)
        job.detonation_job_id = detonation_job_id
        job.detonation_status = detonation_status

    return LinkInspectionJobResponse(
        job_id=job.id,
        status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        result=to_link_inspection_response(
            job.result,
            detonation_job_id=detonation_job_id,
            detonation_status=detonation_status,
        )
        if job.result
        else None,
        error=job.error,
    )


@router.post("/inspect-link/execute/{job_id}")
async def execute_link_inspection_job(
    job_id: str,
    request: Request,
) -> dict[str, str]:
    from backend.main import sandbox_queue

    asyncio.create_task(sandbox_queue.execute_job_by_id(job_id))
    return {"status": "accepted", "job_id": job_id}


# ---------------------------------------------------------------------------
# Detonation endpoints
# ---------------------------------------------------------------------------

@router.post("/detonation/submit", response_model=DetonationJobCreateResponse)
@limiter.limit("10/minute")
async def submit_detonation(
    request: Request,
    request_body: DetonationRequest = Body(...),
    x_sandbox_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> DetonationJobCreateResponse:
    from backend.main import detonation_manager, mailbox_store, settings, telemetry

    verify_sandbox_access(mailbox_store, settings.link_sandbox_api_key, x_sandbox_key, authorization)
    telemetry.increment("detonation.submit.requests")
    job = await detonation_manager.submit(request_body.url, source_email=request_body.source_email)
    if job.status in {"failed", "disabled"}:
        telemetry.increment("detonation.submit.failed")
    else:
        telemetry.increment("detonation.submit.accepted")
    return DetonationJobCreateResponse(job_id=job.id, status=job.status)  # type: ignore[arg-type]


@router.get("/detonation/jobs/{job_id}", response_model=DetonationJobResponse)
@limiter.limit("60/minute")
async def get_detonation_job(
    job_id: str,
    request: Request,
    x_sandbox_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> DetonationJobResponse:
    from backend.main import detonation_manager, mailbox_store, settings

    verify_sandbox_access(mailbox_store, settings.link_sandbox_api_key, x_sandbox_key, authorization)
    job = await detonation_manager.refresh(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="detonation job not found")
    return to_detonation_job_response(job)
