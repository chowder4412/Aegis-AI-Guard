"""Shared FastAPI dependencies: authentication, sandbox access, and rate limiting."""

from __future__ import annotations

import hmac
import logging
from typing import Any

from fastapi import Header, HTTPException, Request
from fastapi.responses import JSONResponse

try:
    from slowapi import Limiter
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address

    SLOWAPI_AVAILABLE = True
except ImportError:  # pragma: no cover
    SLOWAPI_AVAILABLE = False

    class RateLimitExceeded(Exception):
        """Fallback exception type when slowapi is unavailable."""

    def get_remote_address(request: Request) -> str:
        client = request.client
        return client.host if client and client.host else "unknown"

    class Limiter:  # pragma: no cover
        """Minimal no-op limiter used when slowapi is not installed."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            _ = (args, kwargs)

        def limit(self, _value: str):
            def decorator(func):
                return func

            return decorator

logger = logging.getLogger("aegis.backend")


# ---------------------------------------------------------------------------
# Rate limiter (keyed by remote IP)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)


async def rate_limit_exceeded_handler(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})


# ---------------------------------------------------------------------------
# Firebase token authentication
# ---------------------------------------------------------------------------

def require_authenticated_uid(
    mailbox_store,
    authorization: str | None,
) -> str:
    """Extract and verify a Firebase ID token from the Authorization header."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="missing bearer token")

    payload = mailbox_store.verify_id_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="invalid firebase token")

    uid = str(payload.get("uid") or payload.get("sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="firebase token missing uid")

    return uid


# ---------------------------------------------------------------------------
# Sandbox access guard
# ---------------------------------------------------------------------------

def verify_sandbox_access(
    mailbox_store,
    configured_key: str,
    x_sandbox_key: str | None,
    authorization: str | None,
) -> str | None:
    """Allow sandbox access for authenticated users or a matching ops key."""
    if authorization:
        return require_authenticated_uid(mailbox_store, authorization)

    stripped = configured_key.strip()
    if not stripped:
        return None
    if not x_sandbox_key or not hmac.compare_digest(x_sandbox_key.strip(), stripped):
        raise HTTPException(status_code=401, detail="invalid sandbox access")
    return None
