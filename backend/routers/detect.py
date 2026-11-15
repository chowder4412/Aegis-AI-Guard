"""Email phishing detection and AI copilot explanation endpoints."""

import httpx
from fastapi import APIRouter, Body, HTTPException, Request

from backend.dependencies import limiter
from backend.detector import ModelNotReadyError, extract_features
from backend.models import (
    CopilotExplainRequest,
    CopilotExplainResponse,
    CopilotRespondRequest,
    CopilotRespondResponse,
    DetectionResponse,
    EmailFeatures,
    EmailRequest,
)

router = APIRouter()


@router.post("/detect", response_model=DetectionResponse)
@limiter.limit("30/minute")
def detect_email(
    request: Request,
    request_body: EmailRequest = Body(...),
) -> DetectionResponse:
    from backend.main import detector, telemetry

    telemetry.increment("detect.requests")
    try:
        result = detector.predict(request_body.content)
    except ModelNotReadyError as exc:
        telemetry.increment("detect.model_not_ready")
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover
        telemetry.increment("detect.failures")
        raise HTTPException(status_code=500, detail="Email detection failed") from exc

    telemetry.increment("detect.success")
    return DetectionResponse(
        label=result.label,  # type: ignore[arg-type]
        confidence=result.confidence,
        phishing_probability=result.phishing_probability,
        features=EmailFeatures(**result.features),
        model=result.model_name,
    )


@router.post("/copilot/explain", response_model=CopilotExplainResponse)
@limiter.limit("20/minute")
async def copilot_explain(
    request: Request,
    request_body: CopilotExplainRequest = Body(...),
) -> CopilotExplainResponse:
    from backend.main import settings, telemetry

    telemetry.increment("copilot.requests")
    content = request_body.content.strip()
    input_type = request_body.input_type
    features = extract_features(content)

    indicators: list[str] = []
    if features.get("has_ip_url"):
        indicators.append("IP-based direct URL structure (evades DNS reputation)")
    if features.get("num_links", 0) > 2:
        indicators.append(f"Multiple outbound hyperlink references ({features['num_links']} links detected)")
    if features.get("num_suspicious_words", 0) > 0:
        indicators.append("Urgency & credential harvesting keyword signatures detected")
    if features.get("num_exclamations", 0) > 1:
        indicators.append("High punctuation urgency cues (!)")
    if features.get("has_html"):
        indicators.append("HTML payload containing hidden form or anchor elements")

    # If Gemini API key is configured on the backend, optionally invoke Gemini for deep reasoning
    if settings.gemini_api_key:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                prompt = (
                    f"You are Aegis AI Security Copilot. Analyze this {input_type} for cybersecurity threats:\n\n{content[:2000]}\n\n"
                    "Respond with a JSON object containing:\n"
                    '{"summary": "...", "detailed_explanation": "...", "recommended_action": "...", '
                    '"threat_indicators": ["..."], "risk": "Critical|High|Medium|Low", "category": "Phishing|Malware|Spoofing|Social|Other", '
                    '"confidence": 85.0, "impact_score": 7.5, "mitre_technique": "T1566.001", "mitre_tactic": "Initial Access"}'
                )
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.gemini_api_key}"
                resp = await client.post(
                    url,
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"responseMimeType": "application/json"},
                    },
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        import json
                        parsed = json.loads(text)
                        return CopilotExplainResponse(
                            summary=parsed.get("summary") or request_body.summary or f"Suspicious {input_type} intercepted.",
                            detailed_explanation=parsed.get("detailed_explanation") or "Behavioral cues consistent with threat vector.",
                            recommended_action=parsed.get("recommended_action") or "Quarantine immediately and verify sender.",
                            threat_indicators=parsed.get("threat_indicators") or indicators or ["Heuristic evaluation completed"],
                            confidence=float(parsed.get("confidence", 85.0)),
                            risk=parsed.get("risk", "High"),
                            category=parsed.get("category", "Phishing"),
                            impact_score=float(parsed.get("impact_score", 7.5)),
                            mitre_technique=parsed.get("mitre_technique", "T1566.001"),
                            mitre_tactic=parsed.get("mitre_tactic", "Initial Access"),
                            technical_details=[
                                {"label": ind, "description": "Flagged during deep copilot inspection."}
                                for ind in (parsed.get("threat_indicators") or indicators or ["Heuristic anomaly"])
                            ],
                            model="gemini-1.5-flash",
                        )
        except Exception:
            pass

    # Deterministic fallback explanation
    is_threat = bool(indicators) or (request_body.risk_level in {"High", "Critical"})
    summary = request_body.summary or (
        f"High-risk {input_type} detection" if is_threat else f"Clean {input_type} inspection outcome"
    )
    detailed = (
        f"The submitted {input_type} exhibits {len(indicators)} structural threat vectors including credential lures and suspicious redirect patterns."
        if is_threat
        else f"No overt phishing signatures or malicious payloads were identified during structural inspection of this {input_type}."
    )
    action = (
        "Quarantine item and verify the originating sender via an out-of-band communication channel."
        if is_threat
        else "No mitigation necessary. Safe to proceed with normal caution."
    )
    confidence = 88.0 if is_threat else 92.0
    risk = "High" if is_threat else "Low"
    category = "Phishing" if is_threat else "Other"
    impact = 7.5 if is_threat else 2.0

    tech_details = [
        {"label": ind, "description": "Structural anomaly detected by heuristic parser."}
        for ind in indicators
    ] or [{"label": "Structural scan", "description": "Clean syntax and domain structure verified."}]

    return CopilotExplainResponse(
        summary=summary,
        detailed_explanation=detailed,
        recommended_action=action,
        threat_indicators=indicators or ["No high-risk structural anomalies detected"],
        model="aegis-copilot-engine",
        confidence=confidence,
        risk=risk,
        category=category,
        impact_score=impact,
        mitre_technique="T1566.001" if is_threat else "T1589.001",
        mitre_tactic="Initial Access" if is_threat else "Reconnaissance",
        technical_details=tech_details,
    )


@router.post("/copilot/respond", response_model=CopilotRespondResponse)
@limiter.limit("20/minute")
async def copilot_respond(
    request: Request,
    request_body: CopilotRespondRequest = Body(...),
) -> CopilotRespondResponse:
    from backend.main import settings, telemetry

    telemetry.increment("copilot.respond.requests")
    threat_summary = request_body.threat_summary.strip()
    recommendation = request_body.recommendation.strip()

    if settings.gemini_api_key:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                prompt = (
                    f"Based on this threat analysis:\n"
                    f"Threat: {threat_summary}\n"
                    f"Recommendation: {recommendation}\n\n"
                    f"Write a professional, authoritative internal security alert email with clear next steps."
                )
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={settings.gemini_api_key}"
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": prompt}]}]},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
                        if text:
                            return CopilotRespondResponse(draft=text, model="gemini-1.5-flash")
        except Exception:
            pass

    # Deterministic fallback response
    draft = (
        f"SECURITY ALERT NOTIFICATION\n\n"
        f"Incident Summary: {threat_summary}\n\n"
        f"Recommended Action:\n{recommendation}\n\n"
        f"Please do not engage with, click links in, or reply to the referenced message. "
        f"The Security Operations team has isolated this threat for remediation."
    )
    return CopilotRespondResponse(draft=draft, model="aegis-copilot-engine")
