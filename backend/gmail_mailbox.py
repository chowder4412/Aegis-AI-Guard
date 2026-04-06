from __future__ import annotations

import asyncio
import base64
import math
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.detector import ModelNotReadyError, PhishingDetector
from backend.firebase_store import FirebaseMailboxStore
from backend.link_sandbox import LinkSandboxAnalyzer

LINK_REGEX = re.compile(r"https?://[^\s<>\")'\]]+|www\.[^\s<>\")'\]]+", re.IGNORECASE)
MAX_TRACKED_MESSAGE_IDS = 400
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "tiny.cc", "cutt.ly", "rb.gy", "is.gd"}
HIGH_RISK_TLDS = {".zip", ".mov", ".xyz", ".top", ".click", ".gq", ".work", ".cam"}
BRAND_KEYWORDS = {"microsoft", "google", "apple", "amazon", "paypal", "bank", "dhl", "fedex", "dropbox"}


class GmailMailboxError(RuntimeError):
    pass


class BackendGmailMailboxScanner:
    def __init__(
        self,
        *,
        detector: PhishingDetector,
        link_sandbox: LinkSandboxAnalyzer,
        mailbox_store: FirebaseMailboxStore,
        google_oauth_client_id: str,
        google_oauth_client_secret: str,
    ) -> None:
        self._detector = detector
        self._link_sandbox = link_sandbox
        self._mailbox_store = mailbox_store
        self._google_oauth_client_id = google_oauth_client_id
        self._google_oauth_client_secret = google_oauth_client_secret

    async def scan_mailbox(self, uid: str, email: str, limit: int = 12) -> dict[str, Any]:
        session = self._mailbox_store.get_gmail_oauth_session(uid, email)
        if not session:
            raise GmailMailboxError("This Gmail mailbox is not linked on the backend. Reconnect it to continue.")

        normalized_email = email.strip().lower()
        oauth = session.get("oauth") or {}
        scan_state = session.get("scanState") or {}
        processed_message_ids = [
            str(item)
            for item in (scan_state.get("processedMessageIds") or [])
            if isinstance(item, str) and item.strip()
        ][-MAX_TRACKED_MESSAGE_IDS:]

        access_token = str(oauth.get("accessToken") or "").strip()
        refresh_token = str(oauth.get("refreshToken") or "").strip() or None
        id_token = str(oauth.get("idToken") or "").strip() or None
        scope = str(oauth.get("scope") or "").strip() or None
        token_type = str(oauth.get("tokenType") or "Bearer").strip() or "Bearer"
        issued_at = self._coerce_int(oauth.get("issuedAt"))
        expires_in = self._coerce_int(oauth.get("expiresIn"))
        expires_at = self._coerce_int(oauth.get("expiresAt"))

        if not access_token:
            raise GmailMailboxError("The backend Gmail connection does not have an access token. Reconnect the mailbox.")

        session_state: dict[str, Any] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "scope": scope,
            "token_type": token_type,
            "issued_at": issued_at,
            "expires_in": expires_in,
            "expires_at": expires_at,
        }

        async with httpx.AsyncClient(timeout=20.0) as client:
            if self._token_should_refresh(session_state):
                await self._refresh_tokens(client, uid, normalized_email, session_state)

            first_scan = len(processed_message_ids) == 0
            message_ids = await self._list_recent_message_ids(client, session_state, limit, first_scan=first_scan)
            fresh_message_ids = [message_id for message_id in message_ids if message_id not in processed_message_ids]
            alerts: list[dict[str, Any]] = []

            for message_id in fresh_message_ids:
                message = await self._get_message(client, session_state, message_id)
                finding = await self._evaluate_message(message)
                if finding:
                    alerts.append(finding)
                processed_message_ids.append(message_id)

        processed_message_ids = processed_message_ids[-MAX_TRACKED_MESSAGE_IDS:]
        last_synced_at = self._iso_now()
        next_scan_at = self._next_scan_at(len(alerts), len(fresh_message_ids))
        top_signals = self._build_top_signals(alerts, len(fresh_message_ids))
        mailbox_health = "watch" if alerts else "healthy"
        self._mailbox_store.update_gmail_oauth_session(
            uid,
            normalized_email,
            access_token=session_state["access_token"],
            refresh_token=session_state["refresh_token"],
            id_token=session_state["id_token"],
            scope=session_state["scope"],
            token_type=session_state["token_type"],
            expires_in=session_state["expires_in"],
            issued_at=session_state["issued_at"],
            processed_message_ids=processed_message_ids,
            last_backend_scan_at=last_synced_at,
            linked_email_status="active",
            linked_email_last_synced_at=last_synced_at,
            next_scan_at=next_scan_at,
            mailbox_health=mailbox_health,
            consecutive_failures=0,
            last_error="",
            last_alert_count=len(alerts),
            last_alert_at=last_synced_at if alerts else "",
            last_scanned_count=len(fresh_message_ids),
            last_scan_outcome="alerts" if alerts else "clean",
            top_signals=top_signals,
        )

        return {
            "email": normalized_email,
            "scanned_count": len(fresh_message_ids),
            "alert_count": len(alerts),
            "alerts": alerts,
            "last_synced_at": last_synced_at,
            "next_scan_at": next_scan_at,
            "mailbox_health": mailbox_health,
            "consecutive_failures": 0,
            "first_scan_completed": True,
            "top_signals": top_signals,
        }

    async def _list_recent_message_ids(
        self,
        client: httpx.AsyncClient,
        session_state: dict[str, Any],
        limit: int,
        *,
        first_scan: bool = False,
    ) -> list[str]:
        query = {
            "maxResults": str(max(1, min(limit, 30))),
            "q": "in:inbox newer_than:14d"
            if first_scan
            else "in:inbox newer_than:2d",
        }
        payload = await self._gmail_get(client, session_state, "messages", params=query)
        messages = payload.get("messages") or []
        return [str(item.get("id")) for item in messages if isinstance(item, dict) and item.get("id")]

    async def _get_message(self, client: httpx.AsyncClient, session_state: dict[str, Any], message_id: str) -> dict[str, Any]:
        payload = await self._gmail_get(client, session_state, f"messages/{message_id}", params={"format": "full"})
        if not isinstance(payload, dict):
            raise GmailMailboxError(f"Gmail returned an unexpected message payload for {message_id}.")
        return payload

    async def _gmail_get(
        self,
        client: httpx.AsyncClient,
        session_state: dict[str, Any],
        path: str,
        *,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = await client.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/{path}",
            params=params,
            headers={
                "Authorization": f"Bearer {session_state['access_token']}",
                "Accept": "application/json",
            },
        )

        if response.status_code == 401 and session_state.get("refresh_token"):
            await self._refresh_tokens(client, "", "", session_state, persist=False)
            response = await client.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/{path}",
                params=params,
                headers={
                    "Authorization": f"Bearer {session_state['access_token']}",
                    "Accept": "application/json",
                },
            )

        if response.status_code >= 400:
            raise GmailMailboxError(f"Gmail API request failed ({response.status_code}) for {path}.")

        payload = response.json()
        if not isinstance(payload, dict):
            raise GmailMailboxError(f"Gmail returned an invalid payload for {path}.")
        return payload

    async def _refresh_tokens(
        self,
        client: httpx.AsyncClient,
        uid: str,
        email: str,
        session_state: dict[str, Any],
        *,
        persist: bool = True,
    ) -> None:
        refresh_token = session_state.get("refresh_token")
        if not refresh_token:
            raise GmailMailboxError("The saved Gmail access token expired and no refresh token is available. Reconnect the mailbox.")

        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": self._google_oauth_client_id,
                "client_secret": self._google_oauth_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
        if response.status_code >= 400:
            raise GmailMailboxError("The backend could not refresh Gmail access. Reconnect the mailbox.")

        payload = response.json()
        issued_at = int(time.time())
        expires_in = self._coerce_int(payload.get("expires_in")) or 3600
        session_state.update(
            {
                "access_token": str(payload.get("access_token") or "").strip(),
                "refresh_token": str(payload.get("refresh_token") or refresh_token).strip() or refresh_token,
                "id_token": str(payload.get("id_token") or session_state.get("id_token") or "").strip() or None,
                "scope": str(payload.get("scope") or session_state.get("scope") or "").strip() or None,
                "token_type": str(payload.get("token_type") or session_state.get("token_type") or "Bearer").strip() or "Bearer",
                "issued_at": issued_at,
                "expires_in": expires_in,
                "expires_at": issued_at + expires_in,
            }
        )

        if persist and uid and email:
            self._mailbox_store.update_gmail_oauth_session(
                uid,
                email,
                access_token=session_state["access_token"],
                refresh_token=session_state["refresh_token"],
                id_token=session_state["id_token"],
                scope=session_state["scope"],
                token_type=session_state["token_type"],
                expires_in=session_state["expires_in"],
                issued_at=session_state["issued_at"],
            )

    async def _evaluate_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        subject = self._extract_header(payload, "Subject") or "No subject"
        from_address = self._extract_header(payload, "From") or "Unknown sender"
        snippet = str(message.get("snippet") or "").strip()
        payload_text = self._extract_payload_text(payload)
        combined_text = "\n".join(part for part in [subject, snippet, payload_text] if part).strip()
        email_scan = self._analyze_email_content(combined_text)
        links = self._extract_links(combined_text)
        sandbox_candidates = links[:3]
        sandbox_results = (
            await asyncio.gather(
                *(self._safe_link_inspection(link) for link in sandbox_candidates),
                return_exceptions=False,
            )
            if sandbox_candidates
            else []
        )
        suspicious_sandbox = next(
            (
                result
                for result in sandbox_results
                if result
                and (
                    result["risk_score"] >= 65
                    or result["credential_form_detected"]
                    or result["credential_submission_succeeded"]
                    or result["dangerous_download_detected"]
                    or result["verdict"] in {"scam", "suspicious"}
                )
            ),
            None,
        )

        phishing_probability = float(email_scan.get("phishing_probability") or 0.0)
        if not suspicious_sandbox and phishing_probability < 0.6:
            return None

        scan_result = self._build_scan_result(
            subject=subject,
            from_address=from_address,
            snippet=snippet,
            links=links,
            email_scan=email_scan,
            sandbox_result=suspicious_sandbox,
        )

        return {
            "message_id": str(message.get("id") or ""),
            "subject": subject,
            "from_address": from_address,
            "detected_links": links,
            "scan_result": scan_result,
        }

    async def _safe_link_inspection(self, link: str) -> dict[str, Any] | None:
        try:
            result = await self._link_sandbox.inspect(link)
        except Exception:
            return None

        return {
            "verdict": result.verdict,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "reasons": result.reasons,
            "final_url": result.final_url,
            "credential_form_detected": result.credential_form_detected,
            "credential_submission_succeeded": result.credential_submission_succeeded,
            "dangerous_download_detected": result.dangerous_download_detected,
        }

    def _build_scan_result(
        self,
        *,
        subject: str,
        from_address: str,
        snippet: str,
        links: list[str],
        email_scan: dict[str, Any],
        sandbox_result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        base_probability = float(email_scan.get("phishing_probability") or 0.0)
        base_confidence = float(email_scan.get("confidence") or 0.0)
        sandbox_score = int(sandbox_result.get("risk_score") or 0) if sandbox_result else 0
        sandbox_confidence = float(sandbox_result.get("confidence") or 0.0) if sandbox_result else 0.0
        sender_domain = self._extract_sender_domain(from_address)
        link_domains = self._extract_link_domains(links, sandbox_result)
        domain_signals = self._build_domain_signals(subject, from_address, sender_domain, link_domains)
        sender_link_mismatch = bool(sender_domain and link_domains and sender_domain not in link_domains)

        score = max(int(round(base_probability * 100)), sandbox_score)
        if domain_signals:
            score = min(100, max(score, 55 if sender_link_mismatch else 45))
        risk = "Critical" if score >= 85 else "High" if score >= 65 else "Medium" if score >= 40 else "Low"
        category = (
            "Malware"
            if sandbox_result and sandbox_result.get("dangerous_download_detected")
            else "Phishing"
            if sandbox_result and (
                sandbox_result.get("credential_form_detected")
                or sandbox_result.get("credential_submission_succeeded")
                or sandbox_result.get("verdict") in {"scam", "suspicious"}
            )
            else "Phishing"
            if base_probability >= 0.6
            else "Spoofing"
            if sender_link_mismatch and domain_signals
            else "Other"
        )
        summary = (
            "Backend Gmail shield detected suspicious link behavior before inbox interaction."
            if sandbox_result
            else "Backend Gmail shield detected sender and domain anomalies before inbox interaction."
            if domain_signals and category == "Spoofing"
            else "Backend Gmail shield flagged the message content as phishing-like."
        )
        recommendation = (
            "Treat this mailbox item as high risk, quarantine it, and avoid interacting with the embedded links."
            if risk in {"Critical", "High"}
            else "Review the sender and inspect links carefully before any interaction."
        )
        confidence = max(base_confidence, sandbox_confidence)
        technical_details = [
            {"label": "Sender", "description": from_address},
            {"label": "Sender domain", "description": sender_domain or "Unable to extract sender domain."},
            {"label": "Subject", "description": subject},
            {"label": "Detected links", "description": " | ".join(links[:3]) if links else "No links detected in message body."},
            {"label": "Link domains", "description": " | ".join(link_domains[:3]) if link_domains else "No navigable domains detected."},
            {"label": "Model verdict", "description": str(email_scan.get("label") or "unknown")},
            {"label": "Model phishing probability", "description": f"{base_probability:.2f}"},
        ]
        if sender_link_mismatch:
            technical_details.append(
                {
                    "label": "Sender-link mismatch",
                    "description": "The sender domain differs from the domains embedded in the message links.",
                }
            )
        for signal in domain_signals[:4]:
            technical_details.append({"label": "Domain signal", "description": signal})
        if sandbox_result:
            technical_details.extend(
                [
                    {"label": "Sandbox verdict", "description": str(sandbox_result.get("verdict") or "unknown")},
                    {
                        "label": "Credential form detected",
                        "description": "Yes" if sandbox_result.get("credential_form_detected") else "No",
                    },
                    {
                        "label": "Dummy credential accepted",
                        "description": "Yes" if sandbox_result.get("credential_submission_succeeded") else "No",
                    },
                    {
                        "label": "Dangerous download detected",
                        "description": "Yes" if sandbox_result.get("dangerous_download_detected") else "No",
                    },
                ]
            )
            for reason in list(sandbox_result.get("reasons") or [])[:3]:
                technical_details.append({"label": "Sandbox signal", "description": str(reason)})
        if snippet:
            technical_details.append({"label": "Snippet", "description": snippet[:180]})

        return {
            "summary": summary,
            "detailed_summary": f'Backend Gmail scan reviewed "{subject}" from {from_address} and identified risky content, sender, or link signals before user interaction.',
            "confidence": round(confidence, 4),
            "recommendation": recommendation,
            "risk": risk,
            "category": category,
            "impact_score": round(max(1.5, score / 11), 1),
            "mitre_technique": "T1204.002" if category == "Malware" else "T1566.002",
            "mitre_tactic": "Execution" if category == "Malware" else "Initial Access",
            "technical_details": technical_details,
            "analysis_source": "hybrid" if sandbox_result else "backend-model",
            "analysis_source_label": "Backend Gmail shield",
        }

    def _extract_sender_domain(self, from_address: str) -> str:
        match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", from_address)
        return match.group(1).lower() if match else ""

    def _extract_link_domains(self, links: list[str], sandbox_result: dict[str, Any] | None = None) -> list[str]:
        hosts: list[str] = []
        for value in [*links, str(sandbox_result.get("final_url") or "") if sandbox_result else ""]:
            if not value:
                continue
            try:
                host = (urlparse(value).hostname or "").lower()
            except Exception:
                host = ""
            if host and host not in hosts:
                hosts.append(host)
        return hosts

    def _build_domain_signals(self, subject: str, from_address: str, sender_domain: str, link_domains: list[str]) -> list[str]:
        signals: list[str] = []
        subject_and_sender = f"{subject} {from_address}".lower()

        for host in link_domains:
            if host.startswith("xn--"):
                signals.append(f"Punycode-style domain detected: {host}")
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                signals.append(f"IP-based destination detected: {host}")
            if host in SHORTENER_DOMAINS:
                signals.append(f"Link shortener detected: {host}")
            if host.count(".") >= 4:
                signals.append(f"Unusually deep subdomain detected: {host}")
            for tld in HIGH_RISK_TLDS:
                if host.endswith(tld):
                    signals.append(f"High-risk TLD detected: {host}")
                    break

        if sender_domain and link_domains and sender_domain not in link_domains:
            signals.append("Sender domain does not match the domains embedded in the email links.")

        if any(brand in subject_and_sender for brand in BRAND_KEYWORDS):
            foreign_domains = [host for host in link_domains if sender_domain and host != sender_domain]
            if foreign_domains:
                signals.append(f"Brand-style language routes to a different domain: {foreign_domains[0]}")

        return signals

    def _next_scan_at(self, alert_count: int, scanned_count: int) -> str:
        delay_seconds = 300 if alert_count > 0 else 600 if scanned_count > 0 else 1200
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + delay_seconds))

    def _build_top_signals(self, alerts: list[dict[str, Any]], scanned_count: int) -> list[str]:
        signals: list[str] = []
        if scanned_count == 0:
            signals.append("No new inbox messages were available during this pass.")
        for alert in alerts[:3]:
            result = alert.get("scan_result") or {}
            if isinstance(result, dict):
                summary = str(result.get("summary") or "").strip()
                if summary and summary not in signals:
                    signals.append(summary)
                for detail in list(result.get("technical_details") or [])[:2]:
                    if not isinstance(detail, dict):
                        continue
                    description = str(detail.get("description") or "").strip()
                    if description and description not in signals:
                        signals.append(description)
                    if len(signals) >= 4:
                        break
            if len(signals) >= 4:
                break
        if not signals:
            signals.append("Mailbox scan completed without high-risk findings.")
        return signals[:4]

    def _analyze_email_content(self, content: str) -> dict[str, Any]:
        try:
            result = self._detector.predict(content)
            return {
                "label": result.label,
                "confidence": result.confidence,
                "phishing_probability": result.phishing_probability,
            }
        except ModelNotReadyError:
            suspicious_hits = sum(1 for term in ("verify", "password", "urgent", "bank", "login", "click") if term in content.lower())
            probability = min(0.95, 0.2 + suspicious_hits * 0.12 + len(self._extract_links(content)) * 0.15)
            return {
                "label": "phishing" if probability >= 0.5 else "legitimate",
                "confidence": probability,
                "phishing_probability": probability,
            }

    def _extract_header(self, payload: dict[str, Any], header_name: str) -> str:
        headers = payload.get("headers") or []
        for header in headers:
            if not isinstance(header, dict):
                continue
            if str(header.get("name") or "").lower() == header_name.lower():
                return str(header.get("value") or "").strip()
        return ""

    def _extract_payload_text(self, payload: dict[str, Any]) -> str:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
        parts = payload.get("parts") if isinstance(payload.get("parts"), list) else []
        current = self._decode_base64_url(str(body.get("data") or ""))
        children = "\n".join(self._extract_payload_text(part) for part in parts if isinstance(part, dict))
        return "\n".join(item for item in [current, children] if item).strip()

    def _extract_links(self, value: str) -> list[str]:
        seen: set[str] = set()
        links: list[str] = []
        for match in LINK_REGEX.findall(value):
            normalized = match.strip()
            if not normalized:
                continue
            if not normalized.lower().startswith(("http://", "https://")):
                normalized = f"https://{normalized}"
            if normalized in seen:
                continue
            seen.add(normalized)
            links.append(normalized)
        return links

    def _decode_base64_url(self, value: str) -> str:
        if not value:
            return ""
        normalized = value.replace("-", "+").replace("_", "/")
        padding = "=" * ((4 - len(normalized) % 4) % 4)
        try:
            decoded = base64.b64decode(normalized + padding)
            return decoded.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _token_should_refresh(self, session_state: dict[str, Any]) -> bool:
        expires_at = self._coerce_int(session_state.get("expires_at"))
        if not expires_at:
            return False
        return time.time() >= max(0, expires_at - 90)

    def _coerce_int(self, value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _iso_now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
