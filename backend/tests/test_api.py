from __future__ import annotations

from fastapi.testclient import TestClient

import backend.main as main_module
from backend.routers import sandbox as sandbox_router
from backend.detector import DetectorResult, ModelNotReadyError
from backend.link_sandbox import LinkInspectionResult, LinkSandboxError


def sandbox_headers() -> dict[str, str]:
    key = main_module.settings.link_sandbox_api_key.strip()
    return {"x-sandbox-key": key} if key else {}


def auth_headers(token: str = "firebase-token") -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def sandbox_auth_headers(token: str = "firebase-token") -> dict[str, str]:
    return auth_headers(token)


def test_health_returns_expected_shape() -> None:
    client = TestClient(main_module.app)
    response = client.get("/health", headers={"x-request-id": "test-request-id"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert "model_loaded" in payload
    assert "gmail_oauth_ready" in payload
    assert "link_sandbox_enabled" in payload
    assert "decision_threshold" in payload
    assert "model" in payload
    assert response.headers.get("x-request-id") == "test-request-id"


def test_detect_returns_prediction(monkeypatch) -> None:
    client = TestClient(main_module.app)

    def fake_predict(_: str) -> DetectorResult:
        return DetectorResult(
            label="phishing",
            confidence=0.94,
            phishing_probability=0.94,
            features={
                "num_links": 1,
                "has_ip_url": True,
                "num_suspicious_words": 3,
                "num_exclamations": 1,
                "email_length": 100,
                "num_digits": 8,
                "has_html": False,
            },
            model_name="hybridphishingmodel",
        )

    monkeypatch.setattr(main_module.detector, "predict", fake_predict)

    response = client.post("/detect", json={"content": "test suspicious email"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "phishing"
    assert payload["confidence"] == 0.94
    assert payload["phishing_probability"] == 0.94
    assert payload["model"] == "hybridphishingmodel"


def test_detect_rejects_blank_content() -> None:
    client = TestClient(main_module.app)
    response = client.post("/detect", json={"content": "   "})

    assert response.status_code == 422


def test_detect_rejects_oversized_content() -> None:
    client = TestClient(main_module.app)
    response = client.post("/detect", json={"content": "a" * 40_001})

    assert response.status_code == 422


def test_detect_returns_503_when_model_not_ready(monkeypatch) -> None:
    client = TestClient(main_module.app)

    def raise_not_ready(_: str) -> DetectorResult:
        raise ModelNotReadyError("model unavailable")

    monkeypatch.setattr(main_module.detector, "predict", raise_not_ready)
    response = client.post("/detect", json={"content": "test"})

    assert response.status_code == 503
    assert response.json()["detail"] == "model unavailable"


def test_detect_returns_500_on_unexpected_failure(monkeypatch) -> None:
    client = TestClient(main_module.app)

    def raise_unexpected(_: str) -> DetectorResult:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(main_module.detector, "predict", raise_unexpected)
    response = client.post("/detect", json={"content": "test"})

    assert response.status_code == 500
    assert response.json()["detail"] == "Email detection failed"


def test_sandbox_inspect_link_returns_result(monkeypatch) -> None:
    client = TestClient(main_module.app)

    async def fake_inspect(_: str) -> LinkInspectionResult:
        return LinkInspectionResult(
            analysis_id="analysis-1",
            healthy=False,
            verdict="scam",
            risk_score=88,
            confidence=0.91,
            reasons=["credential form detected", "dummy credentials accepted"],
            final_url="https://bad.example/login",
            reputation_flagged=False,
            credential_form_detected=True,
            credential_submission_succeeded=True,
            dangerous_download_detected=False,
        )

    monkeypatch.setattr(main_module.link_sandbox, "inspect", fake_inspect)
    response = client.post("/sandbox/inspect-link", json={"url": "https://bad.example/login"}, headers=sandbox_headers())

    assert response.status_code == 200
    payload = response.json()
    assert payload["healthy"] is False
    assert payload["verdict"] == "scam"
    assert payload["risk_score"] == 88
    assert payload["reputation_flagged"] is False
    assert payload["credential_form_detected"] is True


def test_sandbox_inspect_link_returns_400_for_sandbox_error(monkeypatch) -> None:
    client = TestClient(main_module.app)

    async def raise_error(_: str) -> LinkInspectionResult:
        raise LinkSandboxError("blocked target")

    monkeypatch.setattr(main_module.link_sandbox, "inspect", raise_error)
    response = client.post("/sandbox/inspect-link", json={"url": "https://blocked.example"}, headers=sandbox_headers())

    assert response.status_code == 400
    assert response.json()["detail"] == "blocked target"


def test_sandbox_inspect_link_rejects_invalid_scheme() -> None:
    client = TestClient(main_module.app)
    response = client.post("/sandbox/inspect-link", json={"url": "ftp://example.com"})

    assert response.status_code == 422


def test_sandbox_inspect_link_requires_key_when_configured(monkeypatch) -> None:
    client = TestClient(main_module.app)
    original = main_module.settings.link_sandbox_api_key
    object.__setattr__(main_module.settings, "link_sandbox_api_key", "sandbox-secret")

    async def fake_inspect(_: str) -> LinkInspectionResult:
        return LinkInspectionResult(
            analysis_id="analysis-1",
            healthy=True,
            verdict="safe",
            risk_score=5,
            confidence=0.7,
            reasons=["ok"],
            final_url="https://example.com",
            reputation_flagged=False,
            credential_form_detected=False,
            credential_submission_succeeded=False,
            dangerous_download_detected=False,
        )

    monkeypatch.setattr(main_module.link_sandbox, "inspect", fake_inspect)
    unauthorized = client.post("/sandbox/inspect-link", json={"url": "https://example.com"})
    assert unauthorized.status_code == 401

    key_authorized = client.post(
        "/sandbox/inspect-link",
        json={"url": "https://example.com"},
        headers={"x-sandbox-key": "sandbox-secret"},
    )
    assert key_authorized.status_code == 200

    monkeypatch.setattr(main_module.mailbox_store, "verify_id_token", lambda _: {"uid": "user-123"})
    bearer_authorized = client.post(
        "/sandbox/inspect-link",
        json={"url": "https://example.com"},
        headers=sandbox_auth_headers(),
    )
    assert bearer_authorized.status_code == 200

    object.__setattr__(main_module.settings, "link_sandbox_api_key", original)


def test_sandbox_async_job_flow(monkeypatch) -> None:
    client = TestClient(main_module.app)

    async def fake_inspect(_: str) -> LinkInspectionResult:
        return LinkInspectionResult(
            analysis_id="analysis-async",
            healthy=False,
            verdict="suspicious",
            risk_score=67,
            confidence=0.79,
            reasons=["credential form detected"],
            final_url="https://suspicious.example/login",
            reputation_flagged=True,
            credential_form_detected=True,
            credential_submission_succeeded=False,
            dangerous_download_detected=False,
        )

    monkeypatch.setattr(main_module.link_sandbox, "inspect", fake_inspect)

    created = client.post("/sandbox/inspect-link/async", json={"url": "https://suspicious.example/login"}, headers=sandbox_headers())
    assert created.status_code == 200
    payload = created.json()
    assert payload["status"] == "queued"
    job_id = payload["job_id"]

    # Poll once or twice to allow worker completion.
    first = client.get(f"/sandbox/inspect-link/jobs/{job_id}", headers=sandbox_headers())
    assert first.status_code == 200
    if first.json()["status"] in {"queued", "running"}:
        second = client.get(f"/sandbox/inspect-link/jobs/{job_id}", headers=sandbox_headers())
        assert second.status_code == 200
        job_payload = second.json()
    else:
        job_payload = first.json()

    if job_payload["status"] == "completed":
        assert job_payload["result"]["verdict"] in {"suspicious", "scam", "safe"}


def test_metrics_endpoint_available() -> None:
    client = TestClient(main_module.app)
    response = client.get("/metrics")
    assert response.status_code == 200
    payload = response.json()
    assert "counters" in payload
    assert "routes" in payload


def test_readiness_endpoint_available() -> None:
    client = TestClient(main_module.app)
    response = client.get("/readiness")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ready", "degraded"}
    assert "warnings" in payload
    assert "services" in payload
    assert "model_loaded" in payload["services"]


def test_cors_preflight_allows_localhost_web_origin() -> None:
    client = TestClient(main_module.app)
    response = client.options(
        "/mailboxes/gmail/session",
        headers={
            "origin": "http://localhost:8081",
            "access-control-request-method": "POST",
            "access-control-request-headers": "authorization,content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:8081"
    assert "authorization" in response.headers["access-control-allow-headers"].lower()


def test_store_gmail_mailbox_session_requires_authenticated_user(monkeypatch) -> None:
    client = TestClient(main_module.app)

    monkeypatch.setattr(main_module.mailbox_store, "verify_id_token", lambda _: None)

    response = client.post(
        "/mailboxes/gmail/session",
        json={"email": "user@example.com", "access_token": "access-token-123"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing bearer token"


def test_store_gmail_mailbox_session_persists_backend_tokens(monkeypatch) -> None:
    client = TestClient(main_module.app)
    stored: dict[str, object] = {}

    monkeypatch.setattr(main_module.mailbox_store, "verify_id_token", lambda _: {"uid": "user-123"})

    def fake_save(uid: str, email: str, **kwargs) -> None:
        stored["uid"] = uid
        stored["email"] = email
        stored["payload"] = kwargs

    monkeypatch.setattr(main_module.mailbox_store, "save_gmail_oauth_session", fake_save)

    response = client.post(
        "/mailboxes/gmail/session",
        json={
            "email": "User@Example.com",
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-456",
            "issued_at": 1_700_000_000,
            "expires_in": 3600,
            "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
            "token_type": "Bearer",
        },
        headers=auth_headers(),
    )

    assert response.status_code == 200
    assert response.json() == {"email": "user@example.com", "status": "stored"}
    assert stored["uid"] == "user-123"
    assert stored["email"] == "User@Example.com"
    assert stored["payload"] == {
        "access_token": "access-token-123",
        "refresh_token": "refresh-token-456",
        "id_token": None,
        "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
        "token_type": "Bearer",
        "expires_in": 3600,
        "issued_at": 1_700_000_000,
    }


def test_scan_gmail_mailbox_returns_backend_scan_summary(monkeypatch) -> None:
    client = TestClient(main_module.app)

    monkeypatch.setattr(main_module.mailbox_store, "verify_id_token", lambda _: {"uid": "user-123"})

    async def fake_scan(uid: str, email: str, limit: int):
        assert uid == "user-123"
        assert email == "alerts@example.com"
        assert limit == 5
        return {
            "email": email,
            "scanned_count": 4,
            "alert_count": 1,
            "last_synced_at": "2026-03-27T14:00:00Z",
            "next_scan_at": "2026-03-27T14:10:00Z",
            "mailbox_health": "watch",
            "consecutive_failures": 0,
            "first_scan_completed": True,
            "top_signals": ["Credential harvesting page identified."],
            "alerts": [
                {
                    "message_id": "msg-1",
                    "subject": "Verify your account",
                    "from_address": "attacker@example.com",
                    "detected_links": ["https://bad.example/login"],
                    "scan_result": {
                        "summary": "Phishing indicators detected.",
                        "detailed_summary": "Credential harvesting page identified.",
                        "confidence": 0.93,
                        "recommendation": "Block and quarantine the message.",
                        "risk": "High",
                        "category": "Phishing",
                        "impact_score": 8.9,
                        "mitre_technique": "T1566.002",
                        "mitre_tactic": "Initial Access",
                        "technical_details": [
                            {
                                "label": "Credential form",
                                "description": "A login form was detected on the destination page.",
                            }
                        ],
                        "analysis_source": "backend-model",
                        "analysis_source_label": "hybridphishingmodel",
                    },
                }
            ],
        }

    monkeypatch.setattr(main_module.gmail_mailbox_scanner, "scan_mailbox", fake_scan)

    response = client.post(
        "/mailboxes/gmail/scan",
        json={"email": "alerts@example.com", "limit": 5},
        headers=auth_headers(),
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["email"] == "alerts@example.com"
    assert payload["scanned_count"] == 4
    assert payload["alert_count"] == 1
    assert payload["mailbox_health"] == "watch"
    assert payload["top_signals"] == ["Credential harvesting page identified."]
    assert payload["alerts"][0]["scan_result"]["category"] == "Phishing"


def test_delete_gmail_mailbox_session_removes_backend_record(monkeypatch) -> None:
    client = TestClient(main_module.app)
    deleted: dict[str, str] = {}

    monkeypatch.setattr(main_module.mailbox_store, "verify_id_token", lambda _: {"uid": "user-123"})

    def fake_delete(uid: str, email: str) -> None:
        deleted["uid"] = uid
        deleted["email"] = email

    monkeypatch.setattr(main_module.mailbox_store, "delete_gmail_oauth_session", fake_delete)

    response = client.delete("/mailboxes/gmail/User%40Example.com", headers=auth_headers())

    assert response.status_code == 200
    assert response.json() == {"email": "user@example.com", "status": "deleted"}
    assert deleted == {"uid": "user-123", "email": "user@example.com"}


def test_sandbox_sync_includes_detonation_metadata_when_escalated(monkeypatch) -> None:
    client = TestClient(main_module.app)

    async def fake_inspect(_: str) -> LinkInspectionResult:
        return LinkInspectionResult(
            analysis_id="analysis-det-escalate",
            healthy=False,
            verdict="scam",
            risk_score=91,
            confidence=0.92,
            reasons=["dummy credentials accepted"],
            final_url="https://bad.example/login",
            reputation_flagged=True,
            credential_form_detected=True,
            credential_submission_succeeded=True,
            dangerous_download_detected=False,
        )

    async def fake_auto_escalate(_: str, source_email: str | None = None) -> tuple[str | None, str | None]:
        _ = source_email
        return ("det-job-1", "running")

    monkeypatch.setattr(main_module.link_sandbox, "inspect", fake_inspect)
    monkeypatch.setattr(sandbox_router, "_auto_escalate_detonation", fake_auto_escalate)

    response = client.post("/sandbox/inspect-link", json={"url": "https://bad.example/login"}, headers=sandbox_headers())
    assert response.status_code == 200
    payload = response.json()
    assert payload["detonation_job_id"] == "det-job-1"
    assert payload["detonation_status"] == "running"


def test_detonation_submit_and_poll_job(monkeypatch) -> None:
    client = TestClient(main_module.app)

    class FakeSubmitJob:
        id = "det-job-2"
        status = "running"

    class FakeResult:
        verdict = "malicious"
        risk_score = 97
        confidence = 0.95
        summary = ["credential harvesting observed", "high-confidence malware behavior"]

    class FakeStatusJob:
        id = "det-job-2"
        status = "completed"
        created_at = 1_700_000_000.0
        finished_at = 1_700_000_010.0
        result = FakeResult()
        error = None

    async def fake_submit(url: str, source_email: str | None = None):
        _ = (url, source_email)
        return FakeSubmitJob()

    async def fake_refresh(job_id: str):
        _ = job_id
        return FakeStatusJob()

    monkeypatch.setattr(main_module.detonation_manager, "submit", fake_submit)
    monkeypatch.setattr(main_module.detonation_manager, "refresh", fake_refresh)

    submit_response = client.post(
        "/sandbox/detonation/submit",
        json={"url": "https://suspicious.example/landing", "source_email": "sender@example.com"},
        headers=sandbox_headers(),
    )
    assert submit_response.status_code == 200
    submit_payload = submit_response.json()
    assert submit_payload["job_id"] == "det-job-2"
    assert submit_payload["status"] == "running"

    poll_response = client.get("/sandbox/detonation/jobs/det-job-2", headers=sandbox_headers())
    assert poll_response.status_code == 200
    poll_payload = poll_response.json()
    assert poll_payload["status"] == "completed"
    assert poll_payload["result"]["verdict"] == "malicious"
    assert poll_payload["result"]["risk_score"] == 97
