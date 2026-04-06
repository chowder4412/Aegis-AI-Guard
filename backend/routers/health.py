"""Health, readiness, and metrics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from backend.config import runtime_warnings
from backend.dependencies import limiter
from backend.models import HealthResponse, ReadinessResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
@limiter.limit("60/minute")
def health(request: Request) -> HealthResponse:
    from backend.main import detector, gmail_oauth_ready, settings

    return HealthResponse(
        status="ok",
        model_loaded=detector.ready,
        gmail_oauth_ready=gmail_oauth_ready(),
        link_sandbox_enabled=settings.link_sandbox_enabled,
        decision_threshold=detector.decision_threshold,
        model=detector.model_name,
    )


@router.get("/metrics")
@limiter.limit("30/minute")
def metrics(request: Request) -> dict[str, object]:
    from backend.main import telemetry

    return telemetry.snapshot()


@router.get("/readiness", response_model=ReadinessResponse)
@limiter.limit("30/minute")
def readiness(request: Request) -> ReadinessResponse:
    from backend.main import detector, detonation_manager, gmail_oauth_ready, settings

    warnings = runtime_warnings(settings)
    services = {
        "model_loaded": detector.ready,
        "gmail_oauth_ready": gmail_oauth_ready(),
        "link_sandbox_enabled": settings.link_sandbox_enabled,
        "detonation_enabled": detonation_manager.enabled,
    }
    return ReadinessResponse(
        status="ready" if not warnings and detector.ready else "degraded",
        warnings=warnings,
        services=services,
    )
