from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import firebase_admin
    from firebase_admin import auth as firebase_auth
    from firebase_admin import credentials, firestore
except ImportError:  # pragma: no cover
    firebase_admin = None
    firebase_auth = None
    credentials = None
    firestore = None


class FirebaseMailboxStore:
    def __init__(self, service_account_path: str, database_url: str):
        self._enabled = False
        self._client: Any = None
        self._app: Any = None

        if firebase_admin is None or firestore is None:
            return

        try:
            app = firebase_admin.get_app()
        except ValueError:
            options = {"databaseURL": database_url} if database_url else None

            if service_account_path:
                if credentials is None:
                    return
                path = Path(service_account_path)
                if not path.exists():
                    return
                app = firebase_admin.initialize_app(credentials.Certificate(str(path)), options)
            else:
                # On Cloud Run and other Google runtimes, use Application Default Credentials.
                app = firebase_admin.initialize_app(options=options)
        self._app = app

        try:
            self._client = firestore.client(app=app)
            self._enabled = True
        except Exception:
            self._client = None
            self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled and self._client is not None

    @property
    def auth_enabled(self) -> bool:
        return self._app is not None and firebase_auth is not None

    def verify_id_token(self, token: str) -> dict[str, Any] | None:
        if not self.auth_enabled or firebase_auth is None or self._app is None:
            return None
        try:
            return firebase_auth.verify_id_token(token, app=self._app)
        except Exception:
            return None

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _linked_email_doc(self, uid: str, email: str):
        return (
            self._client.collection("users")
            .document(uid)
            .collection("linkedEmails")
            .document(email.strip().lower().replace("/", "%2F"))
        )

    def _gmail_connection_doc(self, uid: str, email: str):
        return (
            self._client.collection("users")
            .document(uid)
            .collection("gmailConnections")
            .document(email.strip().lower().replace("/", "%2F"))
        )

    def _learning_feedback_collection(self, uid: str):
        return self._client.collection("users").document(uid).collection("learningFeedback")

    def save_linked_mailbox(self, uid: str, email: str) -> None:
        if not self.enabled or not self._client:
            return

        now = self._now_iso()
        doc_ref = self._linked_email_doc(uid, email)
        doc_ref.set(
            {
                "email": email.strip().lower(),
                "linkedAt": now,
                "lastSyncedAt": now,
                "hasCompletedInitialScan": False,
                "status": "active",
                "provider": "gmail-oauth",
                "health": "healthy",
                "lastAlertCount": 0,
                "lastScannedCount": 0,
                "lastScanOutcome": "clean",
                "nextScheduledScanAt": now,
                "consecutiveFailures": 0,
                "topSignals": [],
            },
            merge=True,
        )

    def save_gmail_oauth_session(
        self,
        uid: str,
        email: str,
        *,
        access_token: str,
        refresh_token: str | None = None,
        id_token: str | None = None,
        scope: str | None = None,
        token_type: str | None = None,
        expires_in: int | None = None,
        issued_at: int | None = None,
    ) -> None:
        if not self.enabled or not self._client:
            return

        normalized = email.strip().lower()
        now = self._now_iso()
        expires_at = None
        if issued_at is not None and expires_in is not None:
            expires_at = issued_at + expires_in

        self.save_linked_mailbox(uid, normalized)
        self._gmail_connection_doc(uid, normalized).set(
            {
                "email": normalized,
                "provider": "gmail-oauth",
                "linkedAt": now,
                "updatedAt": now,
                "oauth": {
                    "accessToken": access_token,
                    "refreshToken": refresh_token,
                    "idToken": id_token,
                    "scope": scope,
                    "tokenType": token_type or "Bearer",
                    "expiresIn": expires_in,
                    "issuedAt": issued_at,
                    "expiresAt": expires_at,
                },
                "scanState": {
                    "processedMessageIds": [],
                    "lastBackendScanAt": None,
                    "nextScanAt": now,
                    "consecutiveFailures": 0,
                    "lastError": None,
                    "lastAlertCount": 0,
                    "lastAlertAt": None,
                    "lastScannedCount": 0,
                    "lastScanOutcome": "clean",
                    "topSignals": [],
                },
            },
            merge=True,
        )

    def get_gmail_oauth_session(self, uid: str, email: str) -> dict[str, Any] | None:
        if not self.enabled or not self._client:
            return None

        snapshot = self._gmail_connection_doc(uid, email).get()
        if not snapshot.exists:
            return None
        data = snapshot.to_dict() or {}
        if not isinstance(data, dict):
            return None
        return data

    def update_gmail_oauth_session(
        self,
        uid: str,
        email: str,
        *,
        access_token: str | None = None,
        refresh_token: str | None = None,
        id_token: str | None = None,
        scope: str | None = None,
        token_type: str | None = None,
        expires_in: int | None = None,
        issued_at: int | None = None,
        processed_message_ids: list[str] | None = None,
        last_backend_scan_at: str | None = None,
        linked_email_status: str | None = None,
        linked_email_last_synced_at: str | None = None,
        next_scan_at: str | None = None,
        mailbox_health: str | None = None,
        consecutive_failures: int | None = None,
        last_error: str | None = None,
        last_alert_count: int | None = None,
        last_alert_at: str | None = None,
        last_scanned_count: int | None = None,
        last_scan_outcome: str | None = None,
        top_signals: list[str] | None = None,
    ) -> None:
        if not self.enabled or not self._client:
            return

        update_data: dict[str, Any] = {
            "updatedAt": self._now_iso(),
        }
        if access_token is not None:
            update_data["oauth.accessToken"] = access_token
        if refresh_token is not None:
            update_data["oauth.refreshToken"] = refresh_token
        if id_token is not None:
            update_data["oauth.idToken"] = id_token
        if scope is not None:
            update_data["oauth.scope"] = scope
        if token_type is not None:
            update_data["oauth.tokenType"] = token_type
        if expires_in is not None:
            update_data["oauth.expiresIn"] = expires_in
        if issued_at is not None:
            update_data["oauth.issuedAt"] = issued_at
        if issued_at is not None and expires_in is not None:
            update_data["oauth.expiresAt"] = issued_at + expires_in
        if processed_message_ids is not None:
            update_data["scanState.processedMessageIds"] = processed_message_ids
        if last_backend_scan_at is not None:
            update_data["scanState.lastBackendScanAt"] = last_backend_scan_at
        if next_scan_at is not None:
            update_data["scanState.nextScanAt"] = next_scan_at
        if consecutive_failures is not None:
            update_data["scanState.consecutiveFailures"] = consecutive_failures
        if last_error is not None:
            update_data["scanState.lastError"] = last_error
        if last_alert_count is not None:
            update_data["scanState.lastAlertCount"] = last_alert_count
        if last_alert_at is not None:
            update_data["scanState.lastAlertAt"] = last_alert_at
        if last_scanned_count is not None:
            update_data["scanState.lastScannedCount"] = last_scanned_count
        if last_scan_outcome is not None:
            update_data["scanState.lastScanOutcome"] = last_scan_outcome
        if top_signals is not None:
            update_data["scanState.topSignals"] = top_signals

        self._gmail_connection_doc(uid, email).set(update_data, merge=True)

        linked_updates: dict[str, Any] = {}
        if linked_email_status is not None:
            linked_updates["status"] = linked_email_status
        if linked_email_last_synced_at is not None:
            linked_updates["lastSyncedAt"] = linked_email_last_synced_at
        if next_scan_at is not None:
            linked_updates["nextScheduledScanAt"] = next_scan_at
        if mailbox_health is not None:
            linked_updates["health"] = mailbox_health
        if consecutive_failures is not None:
            linked_updates["consecutiveFailures"] = consecutive_failures
        if last_error is not None:
            linked_updates["lastError"] = last_error
        if last_alert_count is not None:
            linked_updates["lastAlertCount"] = last_alert_count
        if last_alert_at is not None:
            linked_updates["lastAlertAt"] = last_alert_at
        if last_scanned_count is not None:
            linked_updates["lastScannedCount"] = last_scanned_count
        if last_scan_outcome is not None:
            linked_updates["lastScanOutcome"] = last_scan_outcome
        if top_signals is not None:
            linked_updates["topSignals"] = top_signals
        if last_scan_outcome in {"clean", "alerts"}:
            linked_updates["hasCompletedInitialScan"] = True
        if linked_updates:
            self._linked_email_doc(uid, email).set(linked_updates, merge=True)

    def mark_gmail_scan_failure(self, uid: str, email: str, error_message: str) -> None:
        if not self.enabled or not self._client:
            return

        session = self.get_gmail_oauth_session(uid, email) or {}
        scan_state = session.get("scanState") or {}
        try:
            previous_failures = int(scan_state.get("consecutiveFailures") or 0)
        except (TypeError, ValueError):
            previous_failures = 0
        consecutive_failures = previous_failures + 1
        next_scan_delay_minutes = min(30, 5 * consecutive_failures)
        next_scan_at = datetime.now(timezone.utc).timestamp() + (next_scan_delay_minutes * 60)
        next_scan_iso = datetime.fromtimestamp(next_scan_at, tz=timezone.utc).isoformat()

        self.update_gmail_oauth_session(
            uid,
            email,
            linked_email_status="error",
            consecutive_failures=consecutive_failures,
            last_error=error_message,
            last_scan_outcome="failed",
            mailbox_health="degraded",
            next_scan_at=next_scan_iso,
        )

    def delete_gmail_oauth_session(self, uid: str, email: str) -> None:
        if not self.enabled or not self._client:
            return
        self._gmail_connection_doc(uid, email).delete()

    def save_learning_feedback(self, uid: str, feedback: dict[str, Any]) -> str | None:
        if not self.enabled or not self._client:
            return None

        now = self._now_iso()
        payload = {
            **feedback,
            "createdAt": now,
            "trainingStatus": "queued",
        }
        doc_ref = self._learning_feedback_collection(uid).document()
        doc_ref.set(payload)
        return now

    def get_learning_status(self, uid: str) -> dict[str, Any]:
        if not self.enabled or not self._client or not hasattr(self._client, "collection"):
            return {
                "status": "disabled",
                "continuous_learning_enabled": False,
                "feedback_count": 0,
                "labeled_feedback_count": 0,
                "latest_feedback_at": None,
                "sources": {},
            }

        query = (
            self._learning_feedback_collection(uid)
            .order_by("createdAt", direction=firestore.Query.DESCENDING)
            .limit(200)
        )
        documents = list(query.stream())

        sources: dict[str, int] = {}
        labeled_feedback_count = 0
        latest_feedback_at: str | None = None

        for document in documents:
            data = document.to_dict() or {}
            source = str(data.get("source") or "unknown").strip() or "unknown"
            sources[source] = sources.get(source, 0) + 1

            user_label = str(data.get("user_label") or "unknown").strip().lower()
            if user_label in {"phishing", "legitimate"}:
                labeled_feedback_count += 1

            if latest_feedback_at is None:
                latest_feedback_at = str(data.get("createdAt") or "") or None

        return {
            "status": "active",
            "continuous_learning_enabled": True,
            "feedback_count": len(documents),
            "labeled_feedback_count": labeled_feedback_count,
            "latest_feedback_at": latest_feedback_at,
            "sources": sources,
        }

    def save_sandbox_job(self, job_id: str, data: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self._client.collection("sandboxJobs").document(job_id).set(data)
        except Exception:
            pass

    def get_sandbox_job(self, job_id: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            doc = self._client.collection("sandboxJobs").document(job_id).get()
            if doc.exists:
                return doc.to_dict()
        except Exception:
            pass
        return None

    def update_sandbox_job(self, job_id: str, updates: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self._client.collection("sandboxJobs").document(job_id).update(updates)
        except Exception:
            pass

    def record_retraining_event(self, uid: str, event_data: dict[str, Any]) -> None:
        if not self.enabled or not self._client:
            return
        try:
            self._client.collection("users").document(uid).collection("retrainingEvents").document().set(event_data)
        except Exception:
            pass

