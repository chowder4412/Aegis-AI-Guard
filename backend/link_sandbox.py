from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

from backend.url_reputation import SafeBrowsingClient

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except ImportError:  # pragma: no cover
    PlaywrightTimeoutError = Exception
    async_playwright = None


Verdict = Literal["safe", "suspicious", "scam", "unreachable", "error"]

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".vbs",
    ".ps1",
    ".hta",
    ".jar",
    ".apk",
    ".zip",
    ".rar",
    ".7z",
}

ERROR_TERMS = ("invalid", "incorrect", "wrong", "error", "failed", "try again")
SUCCESS_TERMS = ("dashboard", "welcome", "account", "wallet", "inbox", "profile")


class LinkSandboxError(RuntimeError):
    pass


@dataclass
class LinkInspectionResult:
    analysis_id: str
    healthy: bool
    verdict: Verdict
    risk_score: int
    confidence: float
    reasons: list[str]
    final_url: str | None
    reputation_flagged: bool
    credential_form_detected: bool
    credential_submission_succeeded: bool
    dangerous_download_detected: bool


class LinkSandboxAnalyzer:
    def __init__(
        self,
        *,
        enabled: bool,
        timeout_seconds: int,
        reputation_client: SafeBrowsingClient | None = None,
        sandbox_service_url: str = "",
    ) -> None:
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self.reputation_client = reputation_client
        self.sandbox_service_url = sandbox_service_url.strip().rstrip("/")

    def _ensure_safe_target(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise LinkSandboxError("only http/https URLs are supported")
        if not parsed.hostname:
            raise LinkSandboxError("URL is missing a hostname")

        host = parsed.hostname.strip().lower()
        if host in {"localhost", "127.0.0.1", "::1"}:
            raise LinkSandboxError("localhost targets are blocked")

        try:
            resolved = socket.getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise LinkSandboxError("unable to resolve URL hostname") from exc

        for entry in resolved:
            ip_text = entry[4][0]
            ip_value = ipaddress.ip_address(ip_text)
            if (
                ip_value.is_private
                or ip_value.is_loopback
                or ip_value.is_link_local
                or ip_value.is_multicast
                or ip_value.is_reserved
                or ip_value.is_unspecified
            ):
                raise LinkSandboxError("target hostname resolves to a blocked network range")

    @staticmethod
    async def _find_credential_inputs(page) -> tuple[bool, list]:
        selectors = [
            "input[type='password']",
            "input[name*='password' i]",
            "input[name*='pass' i]",
            "input[name*='login' i]",
            "input[name*='user' i]",
            "input[name*='email' i]",
            "input[autocomplete='username']",
            "input[autocomplete='current-password']",
        ]

        elements = []
        for selector in selectors:
            locator = page.locator(selector)
            count = await locator.count()
            for index in range(count):
                element = locator.nth(index)
                if await element.is_visible():
                    elements.append(element)
        return (len(elements) > 0, elements)

    @staticmethod
    async def _fill_dummy_credentials(page) -> None:
        fill_map = [
            ("input[type='email']", "audit.user@aegis.invalid"),
            ("input[name*='email' i]", "audit.user@aegis.invalid"),
            ("input[name*='user' i]", "audit_user_001"),
            ("input[name*='login' i]", "audit_user_001"),
            ("input[type='text']", "audit_user_001"),
            ("input[type='password']", "NotARealPassword!123"),
            ("input[name*='pass' i]", "NotARealPassword!123"),
        ]

        for selector, value in fill_map:
            locator = page.locator(selector)
            count = await locator.count()
            for index in range(min(count, 2)):
                element = locator.nth(index)
                try:
                    if await element.is_visible() and await element.is_editable():
                        await element.fill(value)
                except Exception:
                    continue

    @staticmethod
    async def _submit_form(page) -> None:
        submit_selectors = [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Sign in')",
            "button:has-text('Login')",
            "button:has-text('Log in')",
            "button:has-text('Continue')",
            "button:has-text('Verify')",
        ]

        for selector in submit_selectors:
            locator = page.locator(selector)
            if await locator.count() == 0:
                continue
            button = locator.first
            try:
                if await button.is_visible():
                    await button.click(timeout=1_500)
                    return
            except Exception:
                continue

        # Fallback: press Enter on first password field.
        fallback = page.locator("input[type='password']").first
        if await fallback.count() > 0:
            try:
                await fallback.press("Enter")
            except Exception:
                pass

    @staticmethod
    def _domain(url: str) -> str:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower()

    @staticmethod
    def _extension(path: str) -> str:
        if "." not in path:
            return ""
        return path[path.rfind(".") :].lower()

    async def inspect(self, url: str) -> LinkInspectionResult:
        if not self.enabled:
            raise LinkSandboxError("link sandbox analyzer is disabled")

        self._ensure_safe_target(url)

        # If a decoupled sandbox microservice worker is configured, delegate inspection via HTTP
        if self.sandbox_service_url:
            try:
                import httpx

                async with httpx.AsyncClient(timeout=self.timeout_seconds + 5) as client:
                    resp = await client.post(
                        f"{self.sandbox_service_url}/sandbox/inspect-link",
                        json={"url": url},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        return LinkInspectionResult(
                            analysis_id=data.get("analysis_id", uuid.uuid4().hex),
                            healthy=data.get("healthy", True),
                            verdict=data.get("verdict", "safe"),
                            risk_score=data.get("risk_score", 0),
                            confidence=data.get("confidence", 0.0),
                            reasons=data.get("reasons", []),
                            final_url=data.get("final_url"),
                            reputation_flagged=data.get("reputation_flagged", False),
                            credential_form_detected=data.get("credential_form_detected", False),
                            credential_submission_succeeded=data.get("credential_submission_succeeded", False),
                            dangerous_download_detected=data.get("dangerous_download_detected", False),
                        )
            except Exception as exc:
                if async_playwright is None:
                    raise LinkSandboxError(f"sandbox worker error: {exc}") from exc

        if async_playwright is None:
            raise LinkSandboxError("Playwright is not installed on the backend")

        analysis_id = uuid.uuid4().hex
        reasons: list[str] = []
        risk_score = 0
        final_url: str | None = None
        reputation_flagged = False
        credential_form_detected = False
        credential_submission_succeeded = False
        dangerous_download_detected = False

        start = time.perf_counter()

        if self.reputation_client and self.reputation_client.enabled:
            reputation = await self.reputation_client.check_url(url)
            if reputation.flagged:
                reputation_flagged = True
                risk_score = min(100, risk_score + 30)
                reasons.extend(reputation.reasons)
            elif reputation.reasons:
                reasons.extend(reputation.reasons[:1])

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-extensions",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    accept_downloads=False,
                    user_agent="AegisSandboxBot/1.0",
                )
                page = await context.new_page()

                page.set_default_timeout(self.timeout_seconds * 1000)

                async def on_download(download) -> None:
                    nonlocal dangerous_download_detected, risk_score
                    filename = (download.suggested_filename or "").lower()
                    extension = self._extension(filename)
                    if extension in SUSPICIOUS_EXTENSIONS or extension:
                        dangerous_download_detected = True
                        risk_score = min(100, risk_score + 35)
                        reasons.append("download attempted from inspected link")

                page.on("download", on_download)

                response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_seconds * 1000)
                final_url = page.url

                if response is None or response.status >= 400:
                    risk_score = min(100, risk_score + 10)
                    reasons.append("target URL responded with an error status")

                if self._domain(url) != self._domain(final_url):
                    risk_score = min(100, risk_score + 15)
                    reasons.append("navigation redirected to a different domain")

                has_credentials, _ = await self._find_credential_inputs(page)
                credential_form_detected = has_credentials
                if credential_form_detected:
                    risk_score = min(100, risk_score + 25)
                    reasons.append("credential form detected on destination page")

                    await self._fill_dummy_credentials(page)
                    before_url = page.url
                    await self._submit_form(page)
                    await asyncio.sleep(1.2)

                    after_url = page.url
                    html = (await page.content()).lower()
                    has_error = any(term in html for term in ERROR_TERMS)
                    has_success_hint = any(term in html for term in SUCCESS_TERMS)
                    password_fields_after = await page.locator("input[type='password']").count()

                    if (after_url != before_url or has_success_hint or password_fields_after == 0) and not has_error:
                        credential_submission_succeeded = True
                        risk_score = min(100, risk_score + 45)
                        reasons.append("dummy credentials were accepted or progressed without validation failure")

                elapsed = time.perf_counter() - start
                if elapsed > self.timeout_seconds * 0.85:
                    reasons.append("analysis reached near-timeout window")

                await context.close()
                await browser.close()
        except PlaywrightTimeoutError:
            return LinkInspectionResult(
                analysis_id=analysis_id,
                healthy=False,
                verdict="unreachable",
                risk_score=max(risk_score, 20),
                confidence=0.62,
                reasons=unique(reasons + ["sandbox navigation timed out"]),
                final_url=final_url,
                reputation_flagged=reputation_flagged,
                credential_form_detected=credential_form_detected,
                credential_submission_succeeded=credential_submission_succeeded,
                dangerous_download_detected=dangerous_download_detected,
            )
        except LinkSandboxError:
            raise
        except Exception as exc:  # pragma: no cover
            return LinkInspectionResult(
                analysis_id=analysis_id,
                healthy=False,
                verdict="error",
                risk_score=max(risk_score, 15),
                confidence=0.55,
                reasons=unique(reasons + [f"sandbox execution failed: {type(exc).__name__}"]),
                final_url=final_url,
                reputation_flagged=reputation_flagged,
                credential_form_detected=credential_form_detected,
                credential_submission_succeeded=credential_submission_succeeded,
                dangerous_download_detected=dangerous_download_detected,
            )

        if credential_submission_succeeded or dangerous_download_detected or risk_score >= 60:
            verdict: Verdict = "scam"
            healthy = False
            confidence = 0.9
        elif risk_score >= 30:
            verdict = "suspicious"
            healthy = False
            confidence = 0.75
        else:
            verdict = "safe"
            healthy = True
            confidence = 0.7

        if not reasons:
            reasons.append("no high-risk automation indicators were triggered")

        return LinkInspectionResult(
            analysis_id=analysis_id,
            healthy=healthy,
            verdict=verdict,
            risk_score=min(100, max(0, risk_score)),
            confidence=confidence,
            reasons=unique(reasons),
            final_url=final_url,
            reputation_flagged=reputation_flagged,
            credential_form_detected=credential_form_detected,
            credential_submission_succeeded=credential_submission_succeeded,
            dangerous_download_detected=dangerous_download_detected,
        )


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))
