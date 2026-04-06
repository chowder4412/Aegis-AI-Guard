"""Email phishing detection endpoint."""

from fastapi import APIRouter, Body, HTTPException, Request

from backend.dependencies import limiter
from backend.detector import ModelNotReadyError
from backend.models import DetectionResponse, EmailFeatures, EmailRequest

router = APIRouter()


@router.post("/detect", response_model=DetectionResponse)
@limiter.limit("30/minute")
def detect_email(
    request: Request,
    request_body: EmailRequest = Body(...),
) -> DetectionResponse:
    from backend.main import detector, telemetry

    telemetry.increment("detect.requests")
    try:
        result = detector.predict(request_body.content)
    except ModelNotReadyError as exc:
        telemetry.increment("detect.model_not_ready")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        telemetry.increment("detect.failures")
        raise HTTPException(status_code=500, detail="Email detection failed") from exc

    telemetry.increment("detect.success")
    return DetectionResponse(
        label=result.label,  # type: ignore[arg-type]
        confidence=result.confidence,
        phishing_probability=result.phishing_probability,
        features=EmailFeatures(**result.features),
        model=result.model_name,
    )
