from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Literal

import httpx


DetonationStatus = Literal["queued", "running", "completed", "failed", "disabled"]
DetonationVerdict = Literal["pending", "clean", "suspicious", "malicious", "error"]


class DetonationError(RuntimeError):
    pass


@dataclass
class DetonationResult:
    verdict: DetonationVerdict
    risk_score: int
    confidence: float
    summary: list[str]


@dataclass
class DetonationJob:
    id: str
    url: str
    source_email: str | None
    status: DetonationStatus
    created_at: float
    provider_task_id: str | None = None
    finished_at: float | None = None
    result: DetonationResult | None = None
    error: str | None = None


class DetonationServiceClient:
    def __init__(
        self,
        *,
        enabled: bool,
        provider: str,
        base_url: str,
        api_key: str,
        timeout_seconds: int,
    ) -> None:
        self.enabled = enabled
        self.provider = provider.strip().lower() or "generic"
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def submit_url(self, url: str) -> str:
        if not self.enabled:
            raise DetonationError("detonation service is disabled")
        if not self.base_url:
            raise DetonationError("detonation service base URL is not configured")

        if self.provider == "cape":
            endpoint = f"{self.base_url}/tasks/create/url"
            data = {"url": url}
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.post(endpoint, data=data, headers=self._headers())
            if response.status_code >= 400:
                raise DetonationError(f"detonation submit failed ({response.status_code})")
            payload = response.json()
            task_id = payload.get("task_id")
            if task_id is None:
                raise DetonationError("detonation service did not return task_id")
            return str(task_id)

        endpoint = f"{self.base_url}/api/v1/detonate"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(endpoint, json={"url": url}, headers=self._headers())
        if response.status_code >= 400:
            raise DetonationError(f"detonation submit failed ({response.status_code})")
        payload = response.json()
        job_id = payload.get("job_id") or payload.get("id")
        if not job_id:
            raise DetonationError("detonation service did not return job_id")
        return str(job_id)

    async def fetch_status(self, provider_task_id: str) -> tuple[DetonationStatus, DetonationResult | None, str | None]:
        if self.provider == "cape":
            view_endpoint = f"{self.base_url}/tasks/view/{provider_task_id}"
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                view_response = await client.get(view_endpoint, headers=self._headers())
            if view_response.status_code >= 400:
                return ("failed", None, f"detonation status failed ({view_response.status_code})")
            payload = view_response.json()
            task = payload.get("task") if isinstance(payload, dict) else None
            status = str((task or {}).get("status", "")).lower()

            if status in {"pending", "running", "processing"}:
                return ("running", None, None)
            if status not in {"reported", "completed", "success"}:
                return ("failed", None, f"detonation task status={status or 'unknown'}")

            report_endpoint = f"{self.base_url}/tasks/report/{provider_task_id}"
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                report_response = await client.get(report_endpoint, headers=self._headers())
            if report_response.status_code >= 400:
                return ("failed", None, f"detonation report failed ({report_response.status_code})")
            report = report_response.json()

            malscore = 0.0
            if isinstance(report, dict):
                info = report.get("info")
                if isinstance(info, dict):
                    malscore = float(info.get("score", 0) or 0)
                if not malscore:
                    malscore = float(report.get("malscore", 0) or 0)
            risk_score = max(0, min(100, int(round(malscore * 10))))
            if risk_score >= 75:
                verdict: DetonationVerdict = "malicious"
                confidence = 0.9
            elif risk_score >= 45:
                verdict = "suspicious"
                confidence = 0.78
            else:
                verdict = "clean"
                confidence = 0.7

            result = DetonationResult(
                verdict=verdict,
                risk_score=risk_score,
                confidence=confidence,
                summary=[f"cape malscore={malscore:.2f}"],
            )
            return ("completed", result, None)

        endpoint = f"{self.base_url}/api/v1/detonate/{provider_task_id}"
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.get(endpoint, headers=self._headers())
        if response.status_code >= 400:
            return ("failed", None, f"detonation status failed ({response.status_code})")

        payload = response.json()
        raw_status = str(payload.get("status", "")).lower()
        if raw_status in {"queued", "pending"}:
            return ("queued", None, None)
        if raw_status in {"running", "processing"}:
            return ("running", None, None)
        if raw_status in {"failed", "error"}:
            return ("failed", None, str(payload.get("error") or "detonation job failed"))

        verdict_value = str(payload.get("verdict", "pending")).lower()
        if verdict_value not in {"clean", "suspicious", "malicious"}:
            verdict_value = "pending"
        risk_score = max(0, min(100, int(payload.get("risk_score", 0) or 0)))
        confidence = float(payload.get("confidence", 0.7) or 0.7)
        summary = payload.get("summary") if isinstance(payload.get("summary"), list) else []

        result = DetonationResult(
            verdict=verdict_value,  # type: ignore[arg-type]
            risk_score=risk_score,
            confidence=max(0.0, min(1.0, confidence)),
            summary=[str(item) for item in summary][:8],
        )
        return ("completed", result, None)


class DetonationManager:
    def __init__(self, client: DetonationServiceClient, *, job_ttl_seconds: int = 86_400) -> None:
        self.client = client
        self.job_ttl_seconds = max(600, job_ttl_seconds)
        self.jobs: dict[str, DetonationJob] = {}

    @property
    def enabled(self) -> bool:
        return self.client.enabled

    async def submit(self, url: str, source_email: str | None = None) -> DetonationJob:
        self._cleanup()
        if not self.client.enabled:
            job = DetonationJob(
                id=uuid.uuid4().hex,
                url=url,
                source_email=source_email,
                status="disabled",
                created_at=time.time(),
                error="detonation service is disabled",
            )
            self.jobs[job.id] = job
            return job

        job = DetonationJob(
            id=uuid.uuid4().hex,
            url=url,
            source_email=source_email,
            status="queued",
            created_at=time.time(),
        )
        self.jobs[job.id] = job

        try:
            provider_task_id = await self.client.submit_url(url)
            job.provider_task_id = provider_task_id
            job.status = "running"
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)
            job.finished_at = time.time()
        return job

    async def refresh(self, job_id: str) -> DetonationJob | None:
        self._cleanup()
        job = self.jobs.get(job_id)
        if not job:
            return None
        if job.status in {"completed", "failed", "disabled"}:
            return job
        if not job.provider_task_id:
            job.status = "failed"
            job.error = "missing provider task id"
            job.finished_at = time.time()
            return job

        status, result, error = await self.client.fetch_status(job.provider_task_id)
        job.status = status
        if error:
            job.error = error
        if result:
            job.result = result
        if status in {"completed", "failed"}:
            job.finished_at = time.time()
        return job

    def get(self, job_id: str) -> DetonationJob | None:
        self._cleanup()
        return self.jobs.get(job_id)

    def _cleanup(self) -> None:
        now = time.time()
        stale_ids = [
            job_id
            for job_id, job in self.jobs.items()
            if job.finished_at is not None and (now - job.finished_at) > self.job_ttl_seconds
        ]
        for job_id in stale_ids:
            self.jobs.pop(job_id, None)
