# Aegis Backend

FastAPI backend for:
- `POST /detect` phishing detection using a trained decision-tree model
- `GET /oauth/gmail/start` Gmail OAuth launch
- `GET /oauth/gmail/callback` Gmail OAuth callback and app redirect

## Setup

1. Create a virtual environment.
2. Install dependencies:
   `pip install -r backend/requirements-dev.txt`
3. Install browser runtime for Playwright link sandbox:
   `playwright install chromium`
4. Copy `backend/.env.example` to `backend/.env` and fill in:
   - Google OAuth client ID and secret
   - callback URL registered in Google Cloud
   - `OAUTH_STATE_SECRET`
   - `ALLOWED_CORS_ORIGINS` for browser clients like Expo web on `localhost:8081`
   - `PHISHING_MODEL_PATH`
   - `PHISHING_DECISION_THRESHOLD` (recommended `0.60` with hybrid model)
   - `LOG_LEVEL` (`INFO` by default)
   - `LINK_SANDBOX_ENABLED`, `LINK_SANDBOX_TIMEOUT_SECONDS`, `LINK_SANDBOX_CONCURRENCY`, `LINK_SANDBOX_JOB_TTL_SECONDS`, optional `LINK_SANDBOX_API_KEY`
   - optional `SAFE_BROWSING_API_KEY`, `SAFE_BROWSING_TIMEOUT_SECONDS` for reputation enrichment
   - optional malware detonation settings: `DETONATION_ENABLED`, `DETONATION_PROVIDER`, `DETONATION_SERVICE_BASE_URL`, `DETONATION_SERVICE_API_KEY`, `DETONATION_TIMEOUT_SECONDS`, `DETONATION_JOB_TTL_SECONDS`
5. Start the server:
   `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`

## Cloud Run + Firebase Hosting

Production deployment files included:
- [Dockerfile](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/Dockerfile)
- [cloudrun.env.yaml.example](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/cloudrun.env.yaml.example)
- [deploy_cloud_run.ps1](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/deploy_cloud_run.ps1)

Recommended flow:
1. Copy `backend/cloudrun.env.yaml.example` to `backend/cloudrun.env.yaml`
2. Fill real secrets and production values
3. Deploy Cloud Run:
   `powershell -ExecutionPolicy Bypass -File backend/deploy_cloud_run.ps1`
4. Deploy Firebase Hosting rewrites:
   `firebase deploy --only hosting`

Firebase Hosting is configured to proxy these backend paths to Cloud Run:
- `/health`
- `/readiness`
- `/metrics`
- `/detect`
- `/oauth/**`
- `/sandbox/**`

For local Expo web development, allow your browser origin in backend CORS:
- default dev origins already included: `http://localhost:8081`, `http://127.0.0.1:8081`
- production web origin: `https://YOUR_PROJECT.web.app`

Production OAuth callback recommendation:
- `https://YOUR_PROJECT.web.app/oauth/gmail/callback`
- or your custom Firebase Hosting domain equivalent

## Dataset Import + Training

Import datasets into one normalized CSV for training:

`python -m backend.scripts.import_training_datasets --max-enron-rows 20000`

Train and export the phishing model artifact:

`python -m backend.train_detector --dataset backend/data/processed/phishing_training_dataset.csv --text-column content --label-column label --output backend/models/phishing_model.pkl`

Train baseline + balanced artifacts with comparison metrics:

`python -m backend.scripts.train_balanced_detector --dataset backend/data/processed/phishing_training_dataset.csv`

This writes:
- `backend/models/phishing_model.pkl` (baseline)
- `backend/models/phishing_model_balanced.pkl` (balanced)
- `backend/models/phishing_model_comparison.json` (side-by-side metrics)

Train the production hybrid artifact (TF-IDF + engineered features):

`python -m backend.scripts.train_hybrid_detector --dataset backend/data/processed/phishing_training_dataset.csv`

This writes:
- `backend/models/phishing_model_hybrid.pkl` (recommended runtime model)
- `backend/models/phishing_model_hybrid_metrics.json` (validation threshold sweep + test metrics at selected threshold)

This importer currently pulls from:
- Enron corpus (CMU)
- Apache SpamAssassin public corpus
- Hugging Face phishing/benign JSONL

It also records source status for:
- Zenodo record `5812202` (publication PDF, no downloadable email rows)
- Sting9 public dataset repository (currently no downloadable rows)

## Gmail OAuth Flow

The mobile app opens:

`GET /oauth/gmail/start?uid=<firebase-uid>&redirect_uri=aegisguard://oauth/gmail`

The backend:
- validates the final client redirect URI
- stores `uid` and final redirect URI inside a signed state token
- redirects the browser to Google OAuth

Google redirects back to:

`GET /oauth/gmail/callback?code=...&state=...`

The backend:
- verifies signed state
- exchanges the code for tokens
- fetches the Google account email
- optionally stores the linked mailbox in Firestore if `FIREBASE_SERVICE_ACCOUNT_PATH` is configured
- redirects to the app:
  - success: `aegisguard://oauth/gmail?status=success&email=user@example.com`
  - error: `aegisguard://oauth/gmail?status=error&error=access_denied`

## Detection Endpoint

`POST /detect`

Request:

```json
{
  "content": "URGENT! Verify your bank account now at http://192.168.0.1/login"
}
```

Response:

```json
{
  "label": "phishing",
  "confidence": 0.93,
  "phishing_probability": 0.93,
  "features": {
    "num_links": 1,
    "has_ip_url": true,
    "num_suspicious_words": 3,
    "num_exclamations": 1,
    "email_length": 72,
    "num_digits": 8,
    "has_html": false
  },
  "model": "decision-tree"
}
```

`label` is determined by comparing `phishing_probability` against `PHISHING_DECISION_THRESHOLD`.

If the model file is missing or invalid, the endpoint returns `503` instead of fabricating a result.

## Link Sandbox Endpoint

`POST /sandbox/inspect-link`

Request:

```json
{
  "url": "https://example-login-check.com/session"
}
```

Response:

```json
{
  "analysis_id": "8f3c...",
  "healthy": false,
  "verdict": "scam",
  "risk_score": 84,
  "confidence": 0.9,
  "reasons": [
    "credential form detected on destination page",
    "dummy credentials were accepted or progressed without validation failure"
  ],
  "final_url": "https://example-login-check.com/account",
  "credential_form_detected": true,
  "credential_submission_succeeded": true,
  "dangerous_download_detected": false
}
```

Notes:
- The browser automation runs server-side only; the mobile client receives only the verdict payload.
- Private/internal network targets are blocked to reduce SSRF risk.
- Set `LINK_SANDBOX_API_KEY` and send `X-Sandbox-Key` header to protect this endpoint.
- If `SAFE_BROWSING_API_KEY` is configured, reputation signals are added to the verdict.

Asynchronous queue mode:
- `POST /sandbox/inspect-link/async` enqueues inspection and returns `job_id`.
- `GET /sandbox/inspect-link/jobs/{job_id}` returns queued/running/completed/failed status.
- high-risk results auto-escalate to detonation and include `detonation_job_id` / `detonation_status` in the response payload.

Detonation mode:
- `POST /sandbox/detonation/submit` submits a URL to the malware detonation provider.
- `GET /sandbox/detonation/jobs/{job_id}` returns queued/running/completed/failed/disabled status and risk verdict.
- provider options:
  - `DETONATION_PROVIDER=generic` expects `/api/v1/detonate` + `/api/v1/detonate/{id}`
  - `DETONATION_PROVIDER=cape` expects CAPE endpoints (`/tasks/create/url`, `/tasks/view/{id}`, `/tasks/report/{id}`)

Operational metrics:
- `GET /metrics` returns request counters and route latency/error statistics for observability dashboards.

## Sandbox Isolation (Recommended)

Run the backend sandbox in an isolated container/VM (separate from app and database hosts), for example:

- dedicated VM/container runtime
- non-root user
- dropped Linux capabilities
- no mounted host volumes
- outbound egress controls
- memory/CPU/pids limits

This ensures potential trojan/phishing payload behavior is contained away from end-user devices.

Example hardened runtime:

`docker compose -f backend/docker-compose.sandbox.yml up --build`

The compose file uses:
- non-root container user
- dropped capabilities
- `no-new-privileges`
- read-only filesystem + tmpfs scratch space
- strict memory/CPU/pid limits

## Quality Gates

Install backend runtime + test dependencies:

`pip install -r backend/requirements-dev.txt`

Run backend tests:

`pytest -q backend/tests`
