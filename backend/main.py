from __future__ import annotations

import asyncio
import logging
import sys
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings, runtime_warnings
from backend.dependencies import (
    SLOWAPI_AVAILABLE,
    RateLimitExceeded,
    limiter,
    rate_limit_exceeded_handler,
)
from backend.detonation import DetonationManager, DetonationServiceClient
from backend.detector import PhishingDetector
from backend.firebase_store import FirebaseMailboxStore
from backend.gmail_mailbox import BackendGmailMailboxScanner
from backend.link_sandbox import LinkSandboxAnalyzer
from backend.routers import detect as detect_router
from backend.routers import health as health_router
from backend.routers import mailbox as mailbox_router
from backend.routers import oauth as oauth_router
from backend.routers import sandbox as sandbox_router
from backend.sandbox_queue import SandboxQueue
from backend.telemetry import TelemetryStore
from backend.url_reputation import SafeBrowsingClient

if (
    sys.platform == "win32"
    and sys.version_info < (3, 14)
    and hasattr(asyncio, "WindowsProactorEventLoopPolicy")
):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())


# ---------------------------------------------------------------------------
# Settings & service singletons
# ---------------------------------------------------------------------------

settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO))
logger = logging.getLogger("aegis.backend")
telemetry = TelemetryStore()
startup_warnings = runtime_warnings(settings)

detector = PhishingDetector(
    settings.phishing_model_path,
    decision_threshold=settings.phishing_decision_threshold,
)
mailbox_store = FirebaseMailboxStore(
    service_account_path=settings.firebase_service_account_path,
    database_url=settings.firebase_storage_database_url,
)
safe_browsing = SafeBrowsingClient(
    api_key=settings.safe_browsing_api_key,
    timeout_seconds=settings.safe_browsing_timeout_seconds,
)
link_sandbox = LinkSandboxAnalyzer(
    enabled=settings.link_sandbox_enabled,
    timeout_seconds=settings.link_sandbox_timeout_seconds,
    reputation_client=safe_browsing,
)
gmail_mailbox_scanner = BackendGmailMailboxScanner(
    detector=detector,
    link_sandbox=link_sandbox,
    mailbox_store=mailbox_store,
    google_oauth_client_id=settings.google_oauth_client_id,
    google_oauth_client_secret=settings.google_oauth_client_secret,
)
sandbox_queue = SandboxQueue(
    link_sandbox,
    max_concurrency=settings.link_sandbox_concurrency,
    job_ttl_seconds=settings.link_sandbox_job_ttl_seconds,
)
detonation_client = DetonationServiceClient(
    enabled=settings.detonation_enabled,
    provider=settings.detonation_provider,
    base_url=settings.detonation_service_base_url,
    api_key=settings.detonation_service_api_key,
    timeout_seconds=settings.detonation_timeout_seconds,
)
detonation_manager = DetonationManager(
    detonation_client,
    job_ttl_seconds=settings.detonation_job_ttl_seconds,
)


# ---------------------------------------------------------------------------
# Helpers exposed for routers
# ---------------------------------------------------------------------------

def gmail_oauth_ready() -> bool:
    return bool(
        settings.google_oauth_client_id
        and settings.google_oauth_client_secret
        and settings.google_oauth_callback_url
        and settings.oauth_state_secret
    )


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(title="Aegis Backend", version="1.0.0")

# Rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# CORS
if settings.allowed_cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Routers
app.include_router(health_router.router)
app.include_router(detect_router.router)
app.include_router(sandbox_router.router)
app.include_router(mailbox_router.router)
app.include_router(oauth_router.router)

for warning in startup_warnings:
    logger.warning("readiness_warning %s", warning)

if not SLOWAPI_AVAILABLE:
    logger.warning("rate_limiting_disabled slowapi is not installed; request throttling is unavailable")


# ---------------------------------------------------------------------------
# Request logging middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def with_request_logging(request: Request, call_next):
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
    start = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        elapsed_ms = (time.perf_counter() - start) * 1000
        telemetry.record_request(request.url.path, 500, elapsed_ms)
        logger.exception(
            "request_failed request_id=%s method=%s path=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            elapsed_ms,
        )
        raise

    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-Id"] = request_id
    telemetry.record_request(request.url.path, response.status_code, elapsed_ms)
    logger.info(
        "request_complete request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    return response
