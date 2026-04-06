"""Gmail OAuth start and callback endpoints."""

from __future__ import annotations

import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from backend.dependencies import limiter
from backend.oauth_state import OAuthStateError, sign_state, verify_state

router = APIRouter(prefix="/oauth/gmail")


def _validate_client_redirect_uri(redirect_uri: str, allowed_prefixes: tuple[str, ...]) -> str:
    normalized = redirect_uri.strip()
    if not normalized:
        raise HTTPException(status_code=400, detail="redirect_uri is required")

    if not any(normalized.startswith(prefix) for prefix in allowed_prefixes):
        raise HTTPException(status_code=400, detail="redirect_uri is not allowed")

    return normalized


def _build_error_redirect(target: str, message: str) -> str:
    separator = "&" if "?" in target else "?"
    return f"{target}{separator}{urlencode({'status': 'error', 'error': message})}"


@router.get("/start")
@limiter.limit("10/minute")
def gmail_oauth_start(
    request: Request,
    uid: str = Query(min_length=1),
    redirect_uri: str = Query(min_length=1),
) -> RedirectResponse:
    from backend.main import gmail_oauth_ready, settings

    if not gmail_oauth_ready():
        raise HTTPException(status_code=503, detail="Gmail OAuth is not configured on the backend")

    client_redirect_uri = _validate_client_redirect_uri(redirect_uri, settings.allowed_client_redirect_prefixes)
    state_payload: dict[str, Any] = {
        "uid": uid,
        "client_redirect_uri": client_redirect_uri,
        "exp": int(time.time()) + 600,
        "nonce": secrets.token_urlsafe(16),
    }
    state = sign_state(state_payload, settings.oauth_state_secret)

    google_params = {
        "client_id": settings.google_oauth_client_id,
        "redirect_uri": settings.google_oauth_callback_url,
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "state": state,
    }

    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(google_params)}")


@router.get("/callback", response_model=None)
@limiter.limit("10/minute")
async def gmail_oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    from backend.main import mailbox_store, settings

    if not state:
        raise HTTPException(status_code=400, detail="Missing OAuth state")

    try:
        payload = verify_state(state, settings.oauth_state_secret)
    except OAuthStateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    client_redirect_uri = str(payload["client_redirect_uri"])
    uid = str(payload["uid"])

    if error:
        return RedirectResponse(url=_build_error_redirect(client_redirect_uri, error))

    if not code:
        return RedirectResponse(url=_build_error_redirect(client_redirect_uri, "missing_code"))

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": settings.google_oauth_callback_url,
            },
        )

        if token_response.status_code >= 400:
            return RedirectResponse(url=_build_error_redirect(client_redirect_uri, "token_exchange_failed"))

        token_payload = token_response.json()
        access_token = token_payload.get("access_token")
        if not access_token:
            return RedirectResponse(url=_build_error_redirect(client_redirect_uri, "missing_access_token"))
        refresh_token = token_payload.get("refresh_token")
        id_token = token_payload.get("id_token")
        expires_in = token_payload.get("expires_in")
        scope = token_payload.get("scope")
        token_type = token_payload.get("token_type")

        mailbox_profile_response = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if mailbox_profile_response.status_code >= 400:
            return RedirectResponse(url=_build_error_redirect(client_redirect_uri, "gmail_profile_failed"))

        mailbox_profile = mailbox_profile_response.json()
        email = mailbox_profile.get("emailAddress")
        if not isinstance(email, str) or not email.strip():
            return RedirectResponse(url=_build_error_redirect(client_redirect_uri, "missing_email"))

    mailbox_store.save_gmail_oauth_session(
        uid,
        email,
        access_token=str(access_token),
        refresh_token=str(refresh_token).strip() if isinstance(refresh_token, str) else None,
        id_token=str(id_token).strip() if isinstance(id_token, str) else None,
        scope=str(scope).strip() if isinstance(scope, str) else None,
        token_type=str(token_type).strip() if isinstance(token_type, str) else None,
        expires_in=int(expires_in) if isinstance(expires_in, (int, float, str)) and str(expires_in).strip() else None,
        issued_at=int(time.time()),
    )
    separator = "&" if "?" in client_redirect_uri else "?"
    return RedirectResponse(url=f"{client_redirect_uri}{separator}{urlencode({'status': 'success', 'email': email.lower()})}")
