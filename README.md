# Aegis AI Guard

Expo React Native security dashboard for phishing analysis, threat monitoring, and training workflows.

## Run Locally

Prerequisites:
- Node.js
- Expo Go on a device or an Android/iOS simulator
- A Firebase project with Email/Password authentication enabled

1. Install dependencies:
   `npm install`
2. Configure `.env` for your backend:
   - set `EXPO_PUBLIC_PHISHING_API_URL` to the backend base URL, or
   - set `EXPO_PUBLIC_PHISHING_API_HOST` and `EXPO_PUBLIC_PHISHING_API_PORT`
   You can also override the endpoint later from the in-app Settings screen.
3. Optional: set `EXPO_PUBLIC_GEMINI_API_KEY` in `.env`
4. Start Expo:
   `npm start`
5. Open on a target:
   `npm run android`
   `npm run ios`
   `npm run web`

Quality checks:
- Frontend typecheck: `npm run typecheck`
- Backend tests: `npm run test:backend`
- Backend readiness audit: `GET /readiness`

## Backend Service

The repo now includes a real Python backend in [backend/README.md](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/README.md) for:
- `POST /detect` using a trained decision-tree model
- `GET /oauth/gmail/start`
- `GET /oauth/gmail/callback`

Start it with:
`uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`

For physical-device Expo testing, prefer a LAN-reachable backend URL instead of `localhost`.
The repo-level `.env` can point the app at that LAN address, and `backend/.env` should use the same host for `GOOGLE_OAUTH_CALLBACK_URL` when Gmail OAuth is tested on device.

Before deployment, rotate secrets and check readiness:
- replace any local-only OAuth secrets and state secrets
- move backend env values into your deployment secret manager
- call `GET /readiness` and resolve any warnings before production rollout

## Production Deploy

Recommended production shape for this repo:
- Expo app for Android/iOS clients
- Cloud Run for the FastAPI backend
- Firebase Hosting in front of Cloud Run for HTTPS API routing and Google OAuth callback URLs
- Firestore + Firebase Auth for state and identity

Deployment assets already included:
- [backend/Dockerfile](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/Dockerfile)
- [backend/deploy_cloud_run.ps1](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/deploy_cloud_run.ps1)
- [backend/cloudrun.env.yaml.example](c:/Users/user/Desktop/Aegis-Ai-Guard/backend/cloudrun.env.yaml.example)
- [firebase.json](c:/Users/user/Desktop/Aegis-Ai-Guard/firebase.json)
- [hosting/index.html](c:/Users/user/Desktop/Aegis-Ai-Guard/hosting/index.html)

Suggested production rollout:
1. Copy `backend/cloudrun.env.yaml.example` to `backend/cloudrun.env.yaml` and fill real secrets.
2. Deploy the backend:
   `powershell -ExecutionPolicy Bypass -File backend/deploy_cloud_run.ps1`
3. Deploy Firebase Hosting rewrites:
   `firebase deploy --only hosting`
4. Use your Firebase Hosting domain as:
   - `EXPO_PUBLIC_PHISHING_API_URL=https://YOUR_PROJECT.web.app`
   - `GOOGLE_OAUTH_CALLBACK_URL=https://YOUR_PROJECT.web.app/oauth/gmail/callback`
5. Add that exact callback URL to Google Cloud OAuth credentials.

## Google Verification

To prepare for Google OAuth verification for Gmail mailbox linking, the hosted web app now exposes:
- `https://aegis-ai-guard.web.app/privacy`
- `https://aegis-ai-guard.web.app/terms`
- `https://aegis-ai-guard.web.app/support`

The Gmail linking flow is also reduced to the minimum practical scope:
- `https://www.googleapis.com/auth/gmail.readonly`

Use those hosted URLs in the Google Auth Platform consent-screen and verification flow.

## Firebase Setup

1. Ensure `firebase-applet-config.json` points to your Firebase project.
2. Enable Email/Password auth in the Firebase console.
3. Deploy Firestore rules:
   `firebase deploy --only firestore:rules`
4. Gmail linking now works directly in the app with the Firebase Google provider and the native Android/iOS Firebase app registrations.
5. `EXPO_PUBLIC_GMAIL_OAUTH_URL` is now optional and only needed if you want to keep a separate server-side Gmail OAuth connector.

## Notes

- The app now uses Expo as the main runtime.
- Authentication is now backed by Firebase Auth instead of a demo account.
- Threats, logs, linked mailboxes, and scan events are stored under user-scoped Firestore collections.
- The repo is now bound to the Firebase project `aegis-ai-guard` through `.firebaserc`.
- Native Firebase app registrations now exist for:
  - Android: `com.aegis.aiguard`
  - iOS: `com.aegis.aiguard`
- Expo is wired to the downloaded native config files in `firebase-native/`.
- Gmail linking now uses native Google authorization with Gmail scopes and secure on-device token storage.
- Linked Gmail mailboxes now run a pre-delivery threat shield during sync: emails with attached links are inspected for legitimacy, suspicious links are scored as fraud/phishing risk, and alerts are logged before user interaction.
- Backend now includes a hidden Playwright link-sandbox endpoint (`/sandbox/inspect-link`) for server-side credential-form probing with dummy data and scam verdict reporting.
- Sandbox-backed mailbox scans now use the signed-in Firebase user token for app traffic; do not ship a public sandbox API key in the client bundle.
- Email scans use a hybrid flow: backend detector API first, then Gemini second-opinion review on high-risk or borderline results when Gemini is configured.
- The detector endpoint can also be saved from the in-app Settings screen for local/dev switching.
- If Gemini is unavailable, the app continues with an on-device local intelligence engine (weighted URL/email indicators, scoring, explainability, MITRE mapping).
- If the detector API is unavailable, email scans still run through the on-device local intelligence engine and optionally Gemini when configured.
- Gemini access can be configured from the in-app Settings screen and is stored locally for preview use.
- The optional backend Gmail OAuth flow is still available under `backend/` if you want a server-managed connector later.
- CI now runs frontend typecheck plus backend pytest suite on every push/PR via `.github/workflows/ci.yml`.
- Legacy Vite and server files have been removed from the app workflow.
