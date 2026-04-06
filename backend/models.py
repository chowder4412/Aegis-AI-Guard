from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class EmailRequest(BaseModel):
    content: str = Field(min_length=1, max_length=40_000)

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("content must not be blank")
        return value


class EmailFeatures(BaseModel):
    num_links: int
    has_ip_url: bool
    num_suspicious_words: int
    num_exclamations: int
    email_length: int
    num_digits: int
    has_html: bool


class DetectionResponse(BaseModel):
    label: Literal["phishing", "legitimate"]
    confidence: float = Field(ge=0.0, le=1.0)
    phishing_probability: float = Field(ge=0.0, le=1.0)
    features: EmailFeatures
    model: str


class HealthResponse(BaseModel):
    status: Literal["ok"]
    model_loaded: bool
    gmail_oauth_ready: bool
    link_sandbox_enabled: bool
    decision_threshold: float = Field(gt=0.0, lt=1.0)
    model: str


class ReadinessResponse(BaseModel):
    status: Literal["ready", "degraded"]
    warnings: list[str]
    services: dict[str, bool]


class LinkInspectionRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    source_email: str | None = Field(default=None, max_length=320)

    @field_validator("url")
    @classmethod
    def url_must_be_http_or_https(cls, value: str) -> str:
        normalized = value.strip()
        if not (normalized.startswith("http://") or normalized.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return normalized


class LinkInspectionResponse(BaseModel):
    analysis_id: str
    healthy: bool
    verdict: Literal["safe", "suspicious", "scam", "unreachable", "error"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str]
    final_url: str | None = None
    reputation_flagged: bool
    credential_form_detected: bool
    credential_submission_succeeded: bool
    dangerous_download_detected: bool
    detonation_job_id: str | None = None
    detonation_status: Literal["queued", "running", "completed", "failed", "disabled"] | None = None


class LinkInspectionJobCreateResponse(BaseModel):
    job_id: str
    status: Literal["queued"]


class LinkInspectionJobResponse(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: float
    started_at: float | None = None
    finished_at: float | None = None
    result: LinkInspectionResponse | None = None
    error: str | None = None


class DetonationRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    source_email: str | None = Field(default=None, max_length=320)

    @field_validator("url")
    @classmethod
    def detonation_url_must_be_http_or_https(cls, value: str) -> str:
        normalized = value.strip()
        if not (normalized.startswith("http://") or normalized.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        return normalized


class DetonationResultResponse(BaseModel):
    verdict: Literal["pending", "clean", "suspicious", "malicious", "error"]
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: list[str]


class DetonationJobCreateResponse(BaseModel):
    job_id: str
    status: Literal["queued", "running", "failed", "disabled"]


class DetonationJobResponse(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed", "disabled"]
    created_at: float
    finished_at: float | None = None
    result: DetonationResultResponse | None = None
    error: str | None = None


class GmailMailboxSessionRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    access_token: str = Field(min_length=8)
    refresh_token: str | None = None
    id_token: str | None = None
    issued_at: int | None = None
    expires_in: int | None = None
    scope: str | None = None
    token_type: str | None = None


class GmailMailboxSessionResponse(BaseModel):
    email: str
    status: Literal["stored"]


class GmailMailboxScanRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    limit: int = Field(default=12, ge=1, le=30)


class MailboxScanTechnicalDetail(BaseModel):
    label: str
    description: str


class ThreatIntelObservable(BaseModel):
    type: Literal["url", "domain", "sender-domain", "reply-to-domain", "return-path-domain", "ip", "keyword"]
    value: str
    source: Literal["message", "headers", "sandbox", "heuristic"]


class ThreatIntelIndicator(BaseModel):
    key: str
    label: str
    severity: Literal["low", "medium", "high"]
    evidence: str
    source: Literal["model", "sandbox", "domain-analysis", "auth-analysis", "heuristic"]


class ThreatIntelResponse(BaseModel):
    family: Literal[
        "credential-harvest",
        "brand-impersonation",
        "malware-delivery",
        "spoofing",
        "social-engineering",
        "unknown",
    ]
    disposition: Literal["malicious", "suspicious", "clean"]
    tags: list[str]
    provenance: list[str]
    sender_domain: str | None = None
    reply_to_domain: str | None = None
    return_path_domain: str | None = None
    authentication_findings: list[str] = []
    observables: list[ThreatIntelObservable]
    indicators: list[ThreatIntelIndicator]
    evidence_count: int = Field(ge=0)


class MailboxScanResultResponse(BaseModel):
    summary: str
    detailed_summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    recommendation: str
    risk: Literal["Critical", "High", "Medium", "Low"]
    category: Literal["Phishing", "Malware", "Spoofing", "Social", "Other"]
    impact_score: float
    mitre_technique: str
    mitre_tactic: str
    technical_details: list[MailboxScanTechnicalDetail]
    threat_intelligence: ThreatIntelResponse | None = None
    analysis_source: Literal["backend-model", "hybrid", "fallback", "local-intelligence", "gemini"]
    analysis_source_label: str


class GmailMailboxThreatFindingResponse(BaseModel):
    message_id: str
    subject: str
    from_address: str
    detected_links: list[str]
    scan_result: MailboxScanResultResponse


class GmailMailboxScanResponse(BaseModel):
    email: str
    scanned_count: int = Field(ge=0)
    alert_count: int = Field(ge=0)
    alerts: list[GmailMailboxThreatFindingResponse]
    last_synced_at: str
    next_scan_at: str
    mailbox_health: Literal["healthy", "watch", "degraded"]
    consecutive_failures: int = Field(ge=0)
    first_scan_completed: bool
    top_signals: list[str]


class GmailMailboxDeleteResponse(BaseModel):
    email: str
    status: Literal["deleted"]
