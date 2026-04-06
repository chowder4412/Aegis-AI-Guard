import { getCurrentUserIdToken } from '../firebase';
import type { ScanResult } from '../types';
import { getResolvedPhishingApiConfig } from './phishingApiService';

interface BackendMailboxScanTechnicalDetail {
  label: string;
  description: string;
}

interface BackendMailboxScanResult {
  summary: string;
  detailed_summary: string;
  confidence: number;
  recommendation: string;
  risk: ScanResult['risk'];
  category: ScanResult['category'];
  impact_score: number;
  mitre_technique: string;
  mitre_tactic: string;
  technical_details: BackendMailboxScanTechnicalDetail[];
  analysis_source: ScanResult['analysisSource'];
  analysis_source_label: string;
}

interface BackendMailboxThreatFinding {
  message_id: string;
  subject: string;
  from_address: string;
  detected_links: string[];
  scan_result: BackendMailboxScanResult;
}

interface BackendMailboxScanResponse {
  email: string;
  scanned_count: number;
  alert_count: number;
  alerts: BackendMailboxThreatFinding[];
  last_synced_at: string;
  next_scan_at: string;
  mailbox_health: 'healthy' | 'watch' | 'degraded';
  consecutive_failures: number;
  first_scan_completed: boolean;
  top_signals: string[];
}

export interface MailboxThreatFinding {
  messageId: string;
  subject: string;
  from: string;
  detectedLinks: string[];
  risk: ScanResult['risk'];
  category: ScanResult['category'];
  scanResult: ScanResult;
}

export interface MailboxThreatScanSummary {
  email: string;
  scannedCount: number;
  alertCount: number;
  alerts: MailboxThreatFinding[];
  lastSyncedAt: string;
  nextScheduledScanAt: string;
  mailboxHealth: 'healthy' | 'watch' | 'degraded';
  consecutiveFailures: number;
  firstScanCompleted: boolean;
  topSignals: string[];
}

interface GmailMailboxSessionPayload {
  email: string;
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  issued_at?: number;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

const getMailboxBaseUrl = async () => {
  const configured = (await getResolvedPhishingApiConfig()).url.trim();
  if (!configured) {
    return '';
  }

  const base = configured.endsWith('/detect') ? configured.slice(0, -7) : configured;
  return base.replace(/\/$/, '');
};

const getProtectedHeaders = async () => {
  const token = await getCurrentUserIdToken();
  return {
    Accept: 'application/json',
    Authorization: `Bearer ${token}`,
  };
};

const mapBackendScanResult = (payload: BackendMailboxScanResult): ScanResult => ({
  summary: payload.summary,
  detailedSummary: payload.detailed_summary,
  confidence: payload.confidence,
  recommendation: payload.recommendation,
  risk: payload.risk,
  category: payload.category,
  impactScore: payload.impact_score,
  mitreTechnique: payload.mitre_technique,
  mitreTactic: payload.mitre_tactic,
  technicalDetails: payload.technical_details,
  analysisSource: payload.analysis_source,
  analysisSourceLabel: payload.analysis_source_label,
});

export const storeBackendGmailMailboxSession = async (payload: GmailMailboxSessionPayload) => {
  const baseUrl = await getMailboxBaseUrl();
  if (!baseUrl) {
    throw new Error('Backend mailbox service is not configured.');
  }

  const response = await fetch(`${baseUrl}/mailboxes/gmail/session`, {
    method: 'POST',
    headers: {
      ...(await getProtectedHeaders()),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const fallback = 'Unable to store the Gmail session on the backend.';
    let detail = fallback;
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body.detail || fallback;
    } catch {
      detail = fallback;
    }
    throw new Error(detail);
  }
};

export const runBackendGmailMailboxScan = async (email: string, limit = 12): Promise<MailboxThreatScanSummary> => {
  const baseUrl = await getMailboxBaseUrl();
  if (!baseUrl) {
    throw new Error('Backend mailbox service is not configured.');
  }

  const response = await fetch(`${baseUrl}/mailboxes/gmail/scan`, {
    method: 'POST',
    headers: {
      ...(await getProtectedHeaders()),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: email.trim().toLowerCase(),
      limit,
    }),
  });

  if (!response.ok) {
    const fallback = 'Unable to scan the Gmail mailbox from the backend.';
    let detail = fallback;
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body.detail || fallback;
    } catch {
      detail = fallback;
    }
    throw new Error(detail);
  }

  const payload = (await response.json()) as BackendMailboxScanResponse;
  return {
    email: payload.email,
    scannedCount: payload.scanned_count,
    alertCount: payload.alert_count,
    lastSyncedAt: payload.last_synced_at,
    nextScheduledScanAt: payload.next_scan_at,
    mailboxHealth: payload.mailbox_health,
    consecutiveFailures: payload.consecutive_failures,
    firstScanCompleted: payload.first_scan_completed,
    topSignals: payload.top_signals,
    alerts: payload.alerts.map((item) => ({
      messageId: item.message_id,
      subject: item.subject,
      from: item.from_address,
      detectedLinks: item.detected_links,
      risk: item.scan_result.risk,
      category: item.scan_result.category,
      scanResult: mapBackendScanResult(item.scan_result),
    })),
  };
};

export const deleteBackendGmailMailboxSession = async (email: string) => {
  const baseUrl = await getMailboxBaseUrl();
  if (!baseUrl) {
    return;
  }

  const response = await fetch(`${baseUrl}/mailboxes/gmail/${encodeURIComponent(email.trim().toLowerCase())}`, {
    method: 'DELETE',
    headers: await getProtectedHeaders(),
  });

  if (!response.ok && response.status !== 404) {
    throw new Error('Unable to remove the backend Gmail session.');
  }
};
