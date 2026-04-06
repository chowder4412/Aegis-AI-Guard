from __future__ import annotations

import asyncio
from pathlib import Path

from backend.detector import DetectorResult, PhishingDetector
from backend.gmail_mailbox import BackendGmailMailboxScanner
from backend.link_sandbox import LinkSandboxAnalyzer


class DummyMailboxStore:
    pass


class LinklessPhishingDetector(PhishingDetector):
    def __init__(self) -> None:
        super().__init__(Path("missing-model.pkl"), decision_threshold=0.5)

    def predict(self, content: str) -> DetectorResult:
        if "verify" in content.lower() or "password" in content.lower():
            return DetectorResult(
                label="phishing",
                confidence=0.88,
                phishing_probability=0.88,
                features={},
                model_name="test-detector",
            )

        return DetectorResult(
            label="legitimate",
            confidence=0.84,
            phishing_probability=0.16,
            features={},
            model_name="test-detector",
        )


def build_scanner() -> BackendGmailMailboxScanner:
    detector = LinklessPhishingDetector()
    sandbox = LinkSandboxAnalyzer(enabled=False, timeout_seconds=5.0, reputation_client=None)
    return BackendGmailMailboxScanner(
        detector=detector,
        link_sandbox=sandbox,
        mailbox_store=DummyMailboxStore(),
        google_oauth_client_id="client-id",
        google_oauth_client_secret="client-secret",
    )


def test_linkless_gmail_message_can_be_flagged_by_email_nlp() -> None:
    scanner = build_scanner()
    message = {
        "id": "msg-1",
        "snippet": "Urgent verify your payroll password immediately",
        "payload": {
            "headers": [
                {"name": "Subject", "value": "Verify your payroll password"},
                {"name": "From", "value": "security-team@example.com"},
            ],
            "body": {"data": ""},
            "parts": [],
        },
    }

    finding = asyncio.run(scanner._evaluate_message(message))

    assert finding is not None
    assert finding["message_id"] == "msg-1"
    assert finding["detected_links"] == []
    assert finding["scan_result"]["category"] == "Phishing"
    assert finding["scan_result"]["analysis_source"] == "backend-model"


def test_linkless_benign_gmail_message_does_not_raise_alert() -> None:
    scanner = build_scanner()
    message = {
        "id": "msg-2",
        "snippet": "Weekly team sync moved to Friday afternoon",
        "payload": {
            "headers": [
                {"name": "Subject", "value": "Team sync update"},
                {"name": "From", "value": "ops@example.com"},
            ],
            "body": {"data": ""},
            "parts": [],
        },
    }

    finding = asyncio.run(scanner._evaluate_message(message))

    assert finding is None


def test_gmail_message_adds_sender_domain_intelligence_details() -> None:
    scanner = build_scanner()
    message = {
        "id": "msg-3",
        "snippet": "Verify your Microsoft account at https://bit.ly/fake-login immediately",
        "payload": {
            "headers": [
                {"name": "Subject", "value": "Microsoft security verification"},
                {"name": "From", "value": "Microsoft Alerts <alerts@microsoft.com>"},
            ],
            "body": {"data": ""},
            "parts": [],
        },
    }

    finding = asyncio.run(scanner._evaluate_message(message))

    assert finding is not None
    details = finding["scan_result"]["technical_details"]
    labels = [item["label"] for item in details]
    descriptions = [item["description"] for item in details]
    assert "Sender domain" in labels
    assert "Link domains" in labels
    assert any("Link shortener detected" in item for item in descriptions)
