from __future__ import annotations

import os
from dataclasses import dataclass
import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv


load_dotenv(Path(__file__).resolve().parent / ".env")


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str
    phishing_model_path: Path
    phishing_decision_threshold: float
    link_sandbox_enabled: bool
    link_sandbox_timeout_seconds: int
    link_sandbox_concurrency: int
    link_sandbox_job_ttl_seconds: int
    link_sandbox_api_key: str
    safe_browsing_api_key: str
    safe_browsing_timeout_seconds: int
    detonation_enabled: bool
    detonation_provider: str
    detonation_service_base_url: str
    detonation_service_api_key: str
    detonation_timeout_seconds: int
    detonation_job_ttl_seconds: int
    google_oauth_client_id: str
    google_oauth_client_secret: str
    google_oauth_callback_url: str
    oauth_state_secret: str
    allowed_client_redirect_prefixes: tuple[str, ...]
    allowed_cors_origins: tuple[str, ...]
    firebase_service_account_path: str
    firebase_storage_database_url: str
    gemini_api_key: str = ""
    cloud_tasks_project: str = ""
    cloud_tasks_location: str = ""
    cloud_tasks_queue: str = ""
    redis_url: str = ""
    sandbox_service_url: str = ""


def _split_csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def _is_placeholder_secret(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return True
    return normalized.startswith("replace-") or normalized.startswith("your-") or normalized in {
        "changeme",
        "change-me",
        "example",
    }


def _callback_host(value: str) -> str:
    try:
        parsed = urlparse(value.strip())
        return (parsed.hostname or "").strip().lower()
    except Exception:
        return ""


def _is_private_or_local_host(host: str) -> bool:
    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def runtime_warnings(settings: Settings) -> list[str]:
    warnings: list[str] = []

    if settings.link_sandbox_enabled and not settings.link_sandbox_api_key.strip():
        warnings.append("Link sandbox is enabled without LINK_SANDBOX_API_KEY; sandbox endpoints are unauthenticated.")

    if not settings.oauth_state_secret.strip() or len(settings.oauth_state_secret.strip()) < 32 or _is_placeholder_secret(settings.oauth_state_secret):
        warnings.append("OAUTH_STATE_SECRET is missing or weak; use a long random secret before deployment.")

    callback_url = settings.google_oauth_callback_url.strip()
    callback_host = _callback_host(callback_url)
    if callback_url:
        if callback_url.startswith("http://") and not _is_private_or_local_host(callback_host):
            warnings.append("GOOGLE_OAUTH_CALLBACK_URL uses HTTP on a non-local host; use HTTPS in deployed environments.")
        if callback_host == "localhost":
            warnings.append("GOOGLE_OAUTH_CALLBACK_URL points to localhost; physical devices and external users cannot reach it.")
    elif settings.google_oauth_client_id or settings.google_oauth_client_secret:
        warnings.append("Google OAuth credentials are present but GOOGLE_OAUTH_CALLBACK_URL is missing.")

    if settings.google_oauth_client_id and not settings.google_oauth_client_secret:
        warnings.append("GOOGLE_OAUTH_CLIENT_SECRET is missing while Gmail OAuth is configured.")

    if settings.detonation_enabled:
        if settings.detonation_provider not in {"generic", "cape"}:
            warnings.append("DETONATION_PROVIDER is not recognized; supported values are 'generic' and 'cape'.")
        if not settings.detonation_service_base_url:
            warnings.append("Detonation is enabled but DETONATION_SERVICE_BASE_URL is empty.")

    if not settings.phishing_model_path.exists():
        warnings.append("Phishing model artifact is missing at PHISHING_MODEL_PATH.")

    return warnings


def get_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent.parent
    model_path = os.getenv("PHISHING_MODEL_PATH", "backend/models/phishing_model.pkl")

    sandbox_enabled = os.getenv("LINK_SANDBOX_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
    sandbox_timeout = min(max(int(os.getenv("LINK_SANDBOX_TIMEOUT_SECONDS", "20")), 5), 90)
    sandbox_concurrency = min(max(int(os.getenv("LINK_SANDBOX_CONCURRENCY", "2")), 1), 8)
    sandbox_job_ttl_seconds = min(max(int(os.getenv("LINK_SANDBOX_JOB_TTL_SECONDS", "900")), 60), 86_400)
    safe_browsing_timeout = min(max(int(os.getenv("SAFE_BROWSING_TIMEOUT_SECONDS", "6")), 2), 30)
    detonation_enabled = os.getenv("DETONATION_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    detonation_timeout = min(max(int(os.getenv("DETONATION_TIMEOUT_SECONDS", "20")), 5), 180)
    detonation_job_ttl_seconds = min(max(int(os.getenv("DETONATION_JOB_TTL_SECONDS", "86400")), 600), 604_800)

    return Settings(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        phishing_model_path=(base_dir / model_path).resolve() if not Path(model_path).is_absolute() else Path(model_path),
        phishing_decision_threshold=min(max(float(os.getenv("PHISHING_DECISION_THRESHOLD", "0.45")), 0.01), 0.99),
        link_sandbox_enabled=sandbox_enabled,
        link_sandbox_timeout_seconds=sandbox_timeout,
        link_sandbox_concurrency=sandbox_concurrency,
        link_sandbox_job_ttl_seconds=sandbox_job_ttl_seconds,
        link_sandbox_api_key=os.getenv("LINK_SANDBOX_API_KEY", ""),
        safe_browsing_api_key=os.getenv("SAFE_BROWSING_API_KEY", ""),
        safe_browsing_timeout_seconds=safe_browsing_timeout,
        detonation_enabled=detonation_enabled,
        detonation_provider=os.getenv("DETONATION_PROVIDER", "generic").strip().lower() or "generic",
        detonation_service_base_url=os.getenv("DETONATION_SERVICE_BASE_URL", "").strip(),
        detonation_service_api_key=os.getenv("DETONATION_SERVICE_API_KEY", "").strip(),
        detonation_timeout_seconds=detonation_timeout,
        detonation_job_ttl_seconds=detonation_job_ttl_seconds,
        google_oauth_client_id=os.getenv("GOOGLE_OAUTH_CLIENT_ID", ""),
        google_oauth_client_secret=os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", ""),
        google_oauth_callback_url=os.getenv("GOOGLE_OAUTH_CALLBACK_URL", ""),
        oauth_state_secret=os.getenv("OAUTH_STATE_SECRET", ""),
        allowed_client_redirect_prefixes=_split_csv(
            os.getenv("ALLOWED_CLIENT_REDIRECT_PREFIXES", "aegisguard://oauth/gmail")
        ),
        allowed_cors_origins=_split_csv(
            os.getenv(
                "ALLOWED_CORS_ORIGINS",
                "http://localhost:8081,http://127.0.0.1:8081,https://aegis-ai-guard.web.app",
            )
        ),
        firebase_service_account_path=os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH", ""),
        firebase_storage_database_url=os.getenv("FIREBASE_STORAGE_DATABASE_URL", ""),
        gemini_api_key=os.getenv("GEMINI_API_KEY", "") or os.getenv("EXPO_PUBLIC_GEMINI_API_KEY", ""),
        cloud_tasks_project=os.getenv("CLOUD_TASKS_PROJECT", os.getenv("GOOGLE_CLOUD_PROJECT", "")),
        cloud_tasks_location=os.getenv("CLOUD_TASKS_LOCATION", "us-central1"),
        cloud_tasks_queue=os.getenv("CLOUD_TASKS_QUEUE", ""),
        redis_url=os.getenv("REDIS_URL", ""),
        sandbox_service_url=os.getenv("SANDBOX_SERVICE_URL", ""),
    )
