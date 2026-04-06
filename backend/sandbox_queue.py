from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Literal

from backend.link_sandbox import LinkInspectionResult, LinkSandboxAnalyzer, LinkSandboxError


JobStatus = Literal["queued", "running", "completed", "failed"]


@dataclass
class SandboxJob:
    id: str
    url: str
    source_email: str | None
    status: JobStatus
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    result: LinkInspectionResult | None = None
    error: str | None = None
    detonation_job_id: str | None = None
    detonation_status: str | None = None


class SandboxQueue:
    def __init__(
        self,
        analyzer: LinkSandboxAnalyzer,
        *,
        max_concurrency: int = 2,
        job_ttl_seconds: int = 900,
    ) -> None:
        self.analyzer = analyzer
        self.max_concurrency = max(1, max_concurrency)
        self.job_ttl_seconds = max(60, job_ttl_seconds)
        self.jobs: dict[str, SandboxJob] = {}
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._workers_started = False
        self._start_lock = asyncio.Lock()

    async def submit(self, url: str, source_email: str | None) -> SandboxJob:
        await self._ensure_workers_started()
        self._cleanup_expired_jobs()

        job_id = uuid.uuid4().hex
        now = time.time()
        job = SandboxJob(
            id=job_id,
            url=url,
            source_email=source_email,
            status="queued",
            created_at=now,
        )
        self.jobs[job_id] = job
        await self._queue.put(job_id)
        return job

    def get(self, job_id: str) -> SandboxJob | None:
        self._cleanup_expired_jobs()
        return self.jobs.get(job_id)

    async def _ensure_workers_started(self) -> None:
        if self._workers_started:
            return
        async with self._start_lock:
            if self._workers_started:
                return
            for _ in range(self.max_concurrency):
                asyncio.create_task(self._worker_loop())
            self._workers_started = True

    async def _worker_loop(self) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                await self._run_job(job_id)
            finally:
                self._queue.task_done()

    async def _run_job(self, job_id: str) -> None:
        job = self.jobs.get(job_id)
        if not job:
            return

        job.status = "running"
        job.started_at = time.time()
        try:
            result = await self.analyzer.inspect(job.url)
            job.result = result
            job.status = "completed"
        except LinkSandboxError as exc:
            job.status = "failed"
            job.error = str(exc)
        except Exception as exc:  # pragma: no cover
            job.status = "failed"
            job.error = f"sandbox job failed: {type(exc).__name__}"
        finally:
            job.finished_at = time.time()

    def _cleanup_expired_jobs(self) -> None:
        now = time.time()
        stale_ids = [
            job_id
            for job_id, job in self.jobs.items()
            if job.finished_at is not None and (now - job.finished_at) > self.job_ttl_seconds
        ]
        for job_id in stale_ids:
            self.jobs.pop(job_id, None)
