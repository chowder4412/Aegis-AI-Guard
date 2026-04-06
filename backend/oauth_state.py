from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any


class OAuthStateError(ValueError):
    pass


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("utf-8"))


def sign_state(payload: dict[str, Any], secret: str) -> str:
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()
    return f"{_b64encode(payload_bytes)}.{_b64encode(signature)}"


def verify_state(token: str, secret: str) -> dict[str, Any]:
    try:
        payload_part, signature_part = token.split(".", 1)
    except ValueError as exc:
        raise OAuthStateError("Invalid state format") from exc

    payload_bytes = _b64decode(payload_part)
    actual_signature = _b64decode(signature_part)
    expected_signature = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).digest()

    if not hmac.compare_digest(actual_signature, expected_signature):
        raise OAuthStateError("State signature verification failed")

    payload = json.loads(payload_bytes.decode("utf-8"))
    expires_at = payload.get("exp")
    if not isinstance(expires_at, (int, float)) or expires_at < time.time():
        raise OAuthStateError("State has expired")

    return payload
