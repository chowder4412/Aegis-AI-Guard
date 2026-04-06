from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class ReputationResult:
    flagged: bool
    reasons: list[str]


class SafeBrowsingClient:
    def __init__(self, api_key: str, timeout_seconds: int = 6) -> None:
        self.api_key = api_key.strip()
        self.timeout_seconds = timeout_seconds

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def check_url(self, url: str) -> ReputationResult:
        if not self.enabled:
            return ReputationResult(flagged=False, reasons=[])

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        payload = {
            "client": {"clientId": "aegis-ai-guard", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "UNWANTED_SOFTWARE",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(endpoint, json=payload)
            if response.status_code >= 400:
                return ReputationResult(flagged=False, reasons=[f"reputation lookup failed ({response.status_code})"])
            data = response.json()
        except Exception:
            return ReputationResult(flagged=False, reasons=["reputation lookup unavailable"])

        matches = data.get("matches") if isinstance(data, dict) else None
        if not isinstance(matches, list) or not matches:
            return ReputationResult(flagged=False, reasons=[])

        reasons: list[str] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            threat_type = str(match.get("threatType", "UNKNOWN")).lower()
            platform = str(match.get("platformType", "any")).lower()
            reasons.append(f"reputation flagged as {threat_type} ({platform})")

        return ReputationResult(flagged=True, reasons=reasons or ["reputation service flagged URL"])
