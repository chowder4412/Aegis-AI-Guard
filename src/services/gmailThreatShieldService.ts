import * as SecureStore from 'expo-secure-store';
import { getCurrentUserIdToken } from '../firebase';
import { analyzeContentWithLocalIntelligence } from './localIntelligenceService';
import { getResolvedPhishingApiConfig } from './phishingApiService';
import { saveScanEvent } from './securityDataService';
import type { ScanResult } from '../types';

const SCAN_STATE_PREFIX = 'aegis.gmail.threatscan';
const MAX_TRACKED_MESSAGE_IDS = 400;
const LINK_REGEX = /https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi;

interface GmailMessageListResponse {
  messages?: { id: string }[];
}

interface GmailMessageHeader {
  name: string;
  value: string;
}

interface GmailMessageBody {
  size?: number;
  data?: string;
}

interface GmailMessagePayload {
  mimeType?: string;
  headers?: GmailMessageHeader[];
  body?: GmailMessageBody;
  parts?: GmailMessagePayload[];
}

interface GmailMessageResponse {
  id: string;
  threadId?: string;
  internalDate?: string;
  snippet?: string;
  payload?: GmailMessagePayload;
}

interface MailboxThreatScanState {
  processedMessageIds: string[];
  lastScanAt?: string;
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
  scannedCount: number;
  alertCount: number;
  alerts: MailboxThreatFinding[];
}

interface BackendSandboxInspectionResponse {
  healthy: boolean;
  verdict: 'safe' | 'suspicious' | 'scam' | 'unreachable' | 'error';
  risk_score: number;
  confidence: number;
  reasons: string[];
  final_url?: string | null;
  credential_form_detected: boolean;
  credential_submission_succeeded: boolean;
  dangerous_download_detected: boolean;
  detonation_job_id?: string | null;
  detonation_status?: 'queued' | 'running' | 'completed' | 'failed' | 'disabled' | null;
}

interface BackendSandboxAsyncCreateResponse {
  job_id: string;
  status: 'queued';
}

interface BackendSandboxAsyncJobResponse {
  job_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  result?: BackendSandboxInspectionResponse;
  error?: string | null;
}

interface BackendDetonationResultResponse {
  verdict: 'pending' | 'clean' | 'suspicious' | 'malicious' | 'error';
  risk_score: number;
  confidence: number;
  summary: string[];
}

interface BackendDetonationJobResponse {
  job_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'disabled';
  result?: BackendDetonationResultResponse;
  error?: string | null;
}

const toStoreKey = (uid: string, email: string) => `${SCAN_STATE_PREFIX}.${uid}.${encodeURIComponent(email.trim().toLowerCase())}`;

const secureStoreOptions: SecureStore.SecureStoreOptions = {
  keychainService: 'aegis-ai-guard.gmail',
};

const normalizeLink = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
};

const getSandboxEndpoint = async () => {
  const configured = (await getResolvedPhishingApiConfig()).url.trim();
  if (!configured) {
    return '';
  }

  const base = configured.endsWith('/detect') ? configured.slice(0, -7) : configured;
  return `${base.replace(/\/$/, '')}/sandbox/inspect-link`;
};

const getDetonationEndpoint = async () => {
  const configured = (await getResolvedPhishingApiConfig()).url.trim();
  if (!configured) {
    return '';
  }

  const base = configured.endsWith('/detect') ? configured.slice(0, -7) : configured;
  return `${base.replace(/\/$/, '')}/sandbox/detonation`;
};

const getSandboxHeaders = async (withJson = false) => {
  const token = await getCurrentUserIdToken();
  return {
    Accept: 'application/json',
    Authorization: `Bearer ${token}`,
    ...(withJson ? { 'Content-Type': 'application/json' } : {}),
  };
};

const pollDetonationResult = async (jobId: string): Promise<BackendDetonationResultResponse | null> => {
  if (!jobId) {
    return null;
  }

  const endpoint = await getDetonationEndpoint();
  if (!endpoint) {
    return null;
  }

  for (let attempt = 0; attempt < 10; attempt += 1) {
    await new Promise((resolve) => {
      setTimeout(resolve, 1000);
    });

    const response = await fetch(`${endpoint}/jobs/${jobId}`, {
      method: 'GET',
      headers: await getSandboxHeaders(),
    });
    if (!response.ok) {
      return null;
    }

    const payload = (await response.json()) as BackendDetonationJobResponse;
    if (payload.status === 'failed' || payload.status === 'disabled') {
      return null;
    }
    if (payload.status === 'completed' && payload.result) {
      return payload.result;
    }
  }

  return null;
};

const mapSandboxVerdictToScan = (
  link: string,
  payload: BackendSandboxInspectionResponse,
  detonation: BackendDetonationResultResponse | null = null,
): ScanResult => {
  const score = Math.max(0, Math.min(100, Math.round(Math.max(payload.risk_score, detonation?.risk_score || 0))));
  const risk: ScanResult['risk'] = score >= 85 ? 'Critical' : score >= 65 ? 'High' : score >= 40 ? 'Medium' : 'Low';

  const detonationMalicious = detonation?.verdict === 'malicious';
  const detonationSuspicious = detonation?.verdict === 'suspicious';
  const category: ScanResult['category'] =
    payload.dangerous_download_detected || detonationMalicious || detonationSuspicious
      ? 'Malware'
      : payload.credential_form_detected
      ? 'Phishing'
      : payload.healthy
      ? 'Other'
      : 'Spoofing';

  return {
    summary:
      payload.verdict === 'safe' && !detonation
        ? 'Sandbox e2e test did not confirm credential abuse behavior.'
        : 'Sandbox e2e test indicates suspicious credential or malware behavior.',
    detailedSummary: `Backend Playwright sandbox verdict: ${payload.verdict}. Link tested: ${link}.${detonation ? ` Detonation verdict: ${detonation.verdict}.` : ''}`,
    confidence: Math.max(0, Math.min(100, Math.round(Math.max(payload.confidence || 0, detonation?.confidence || 0) * 100))),
    recommendation:
      payload.verdict === 'safe' && !detonationMalicious && !detonationSuspicious
        ? 'Keep monitoring this sender and continue URL validation before interaction.'
        : 'Treat as scam, quarantine the message, and block this destination immediately.',
    risk,
    category,
    impactScore: Number((Math.max(1.5, score / 11)).toFixed(1)),
    mitreTechnique: payload.dangerous_download_detected ? 'T1204.002' : 'T1566.002',
    mitreTactic: payload.dangerous_download_detected ? 'Execution' : 'Initial Access',
    technicalDetails: [
      { label: 'Sandbox verdict', description: payload.verdict },
      { label: 'Credential form detected', description: payload.credential_form_detected ? 'Yes' : 'No' },
      { label: 'Dummy credential accepted', description: payload.credential_submission_succeeded ? 'Yes' : 'No' },
      { label: 'Dangerous download detected', description: payload.dangerous_download_detected ? 'Yes' : 'No' },
      ...(detonation ? [{ label: 'Detonation verdict', description: detonation.verdict }] : []),
      ...(detonation ? [{ label: 'Detonation risk score', description: String(detonation.risk_score) }] : []),
      ...(detonation?.summary || []).slice(0, 2).map((item) => ({ label: 'Detonation signal', description: item })),
      ...(payload.reasons || []).slice(0, 3).map((reason) => ({ label: 'Sandbox reason', description: reason })),
    ],
    analysisSource: 'hybrid',
    analysisSourceLabel: detonation ? 'Backend sandbox + detonation' : 'Backend sandbox e2e',
  };
};

const inspectLinkWithBackendSandbox = async (link: string): Promise<ScanResult | null> => {
  const endpoint = await getSandboxEndpoint();
  if (!endpoint) {
    return null;
  }

  try {
    const createResponse = await fetch(`${endpoint}/async`, {
      method: 'POST',
      headers: await getSandboxHeaders(true),
      body: JSON.stringify({ url: link }),
    });
    if (!createResponse.ok) {
      return null;
    }

    const created = (await createResponse.json()) as BackendSandboxAsyncCreateResponse;
    if (!created?.job_id) {
      return null;
    }

    for (let attempt = 0; attempt < 14; attempt += 1) {
      await new Promise((resolve) => {
        setTimeout(resolve, 850);
      });

      const jobResponse = await fetch(`${endpoint}/jobs/${created.job_id}`, {
        method: 'GET',
        headers: await getSandboxHeaders(),
      });
      if (!jobResponse.ok) {
        return null;
      }

      const jobPayload = (await jobResponse.json()) as BackendSandboxAsyncJobResponse;
      if (jobPayload.status === 'failed') {
        return null;
      }
      if (jobPayload.status === 'completed' && jobPayload.result?.verdict) {
        const detonationResult = jobPayload.result.detonation_job_id
          ? await pollDetonationResult(jobPayload.result.detonation_job_id)
          : null;
        return mapSandboxVerdictToScan(link, jobPayload.result, detonationResult);
      }
    }

    return null;
  } catch {
    return null;
  }
};

const decodeBase64Url = (input?: string) => {
  if (!input) {
    return '';
  }

  if (typeof atob !== 'function') {
    return '';
  }

  try {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const binary = atob(normalized + padding);
    let escaped = '';
    for (let index = 0; index < binary.length; index += 1) {
      const hex = binary.charCodeAt(index).toString(16).padStart(2, '0');
      escaped += `%${hex}`;
    }
    return decodeURIComponent(escaped);
  } catch {
    return '';
  }
};

const extractPayloadText = (payload?: GmailMessagePayload): string => {
  if (!payload) {
    return '';
  }

  const current = decodeBase64Url(payload.body?.data);
  const children = payload.parts?.map((item) => extractPayloadText(item)).filter(Boolean).join('\n') || '';
  return [current, children].filter(Boolean).join('\n').trim();
};

const extractHeader = (payload: GmailMessagePayload | undefined, headerName: string) =>
  payload?.headers?.find((item) => item.name.toLowerCase() === headerName.toLowerCase())?.value?.trim() || '';

const unique = <T,>(items: T[]) => Array.from(new Set(items));

const extractLinks = (value: string) => unique((value.match(LINK_REGEX) || []).map((item) => normalizeLink(item)).filter(Boolean));

const getScanState = async (uid: string, email: string): Promise<MailboxThreatScanState> => {
  const stored = await SecureStore.getItemAsync(toStoreKey(uid, email), secureStoreOptions);
  if (!stored) {
    return { processedMessageIds: [] };
  }

  try {
    const parsed = JSON.parse(stored) as MailboxThreatScanState;
    return {
      processedMessageIds: Array.isArray(parsed.processedMessageIds) ? parsed.processedMessageIds.slice(0, MAX_TRACKED_MESSAGE_IDS) : [],
      lastScanAt: parsed.lastScanAt,
    };
  } catch {
    return { processedMessageIds: [] };
  }
};

const saveScanState = async (uid: string, email: string, state: MailboxThreatScanState) => {
  const trimmedState: MailboxThreatScanState = {
    processedMessageIds: state.processedMessageIds.slice(-MAX_TRACKED_MESSAGE_IDS),
    lastScanAt: state.lastScanAt || new Date().toISOString(),
  };
  await SecureStore.setItemAsync(toStoreKey(uid, email), JSON.stringify(trimmedState), secureStoreOptions);
};

const gmailGet = async <T,>(accessToken: string, path: string): Promise<T> => {
  const response = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/${path}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Gmail API request failed (${response.status}) for ${path}`);
  }

  return (await response.json()) as T;
};

const listRecentMessageIds = async (accessToken: string, limit: number) => {
  const query = new URLSearchParams({
    maxResults: String(limit),
    q: 'newer_than:2d category:primary',
  });
  const payload = await gmailGet<GmailMessageListResponse>(accessToken, `messages?${query.toString()}`);
  return (payload.messages || []).map((item) => item.id).filter(Boolean);
};

const getMessage = async (accessToken: string, messageId: string) =>
  gmailGet<GmailMessageResponse>(accessToken, `messages/${messageId}?format=full`);

const buildAlertResult = (subject: string, from: string, snippet: string, links: string[], linkScan: ScanResult | null, emailScan: ScanResult): ScanResult => {
  const phishingLike =
    linkScan !== null &&
    (linkScan.category === 'Phishing' || linkScan.category === 'Spoofing' || linkScan.risk === 'High' || linkScan.risk === 'Critical');
  const risk = phishingLike && linkScan ? linkScan.risk : emailScan.risk;
  const category: ScanResult['category'] = phishingLike ? 'Phishing' : emailScan.category;
  const confidence = Math.max(linkScan?.confidence || 0, emailScan.confidence);

  return {
    summary:
      phishingLike && linkScan
        ? 'Potential scam detected before inbox interaction: suspicious link behavior found in a newly synced email.'
        : 'Suspicious email patterns were detected during pre-delivery scan.',
    detailedSummary:
      phishingLike && linkScan
        ? `Pre-delivery shield inspected sender "${from}" and found risky link indicators before user interaction. Subject: "${subject}".`
        : `Pre-delivery shield inspected sender "${from}" and flagged suspicious email-language patterns before user interaction. Subject: "${subject}".`,
    confidence,
    recommendation:
      'Do not open the links directly. Move this message to review/quarantine and verify sender legitimacy through a trusted channel.',
    risk,
    category,
    impactScore: Number(Math.max(linkScan?.impactScore || 0, emailScan.impactScore).toFixed(1)),
    mitreTechnique: linkScan?.mitreTechnique || emailScan.mitreTechnique,
    mitreTactic: linkScan?.mitreTactic || emailScan.mitreTactic,
    technicalDetails: [
      { label: 'Sender', description: from || 'Unknown sender' },
      { label: 'Subject', description: subject || 'No subject' },
      { label: 'Detected links', description: links.length ? links.slice(0, 3).join(' | ') : 'No links detected in message body.' },
      ...(linkScan?.technicalDetails || []),
      ...emailScan.technicalDetails.map((item) => ({
        label: `Email signal: ${item.label}`,
        description: item.description,
      })),
      snippet ? { label: 'Snippet', description: snippet.slice(0, 180) } : null,
    ].filter(Boolean) as ScanResult['technicalDetails'],
    analysisSource: 'local-intelligence',
    analysisSourceLabel: 'Pre-delivery link shield',
  };
};

const evaluateMessageForThreat = async (message: GmailMessageResponse): Promise<MailboxThreatFinding | null> => {
  const subject = extractHeader(message.payload, 'Subject');
  const from = extractHeader(message.payload, 'From');
  const payloadText = extractPayloadText(message.payload);
  const snippet = message.snippet || '';
  const combinedText = [subject, snippet, payloadText].filter(Boolean).join('\n');
  const emailScan = analyzeContentWithLocalIntelligence(combinedText, 'email').scanResult;

  const links = extractLinks(combinedText);
  const linkAnalyses = links.map((link) => ({
    link,
    result: analyzeContentWithLocalIntelligence(link, 'url').scanResult,
  }));

  const suspiciousLink = linkAnalyses
    .sort((first, second) => second.result.confidence - first.result.confidence)
    .find((entry) => entry.result.risk === 'Critical' || entry.result.risk === 'High' || entry.result.category === 'Phishing' || entry.result.category === 'Spoofing');

  const sandboxCandidates = links.slice(0, 3);
  const sandboxResults = await Promise.all(sandboxCandidates.map((link) => inspectLinkWithBackendSandbox(link)));
  const sandboxSuspicious = sandboxResults
    .filter((item): item is ScanResult => Boolean(item))
    .sort((first, second) => second.confidence - first.confidence)
    .find((item) => item.risk === 'Critical' || item.risk === 'High' || item.category === 'Phishing' || item.category === 'Malware');

  const emailSuspicious =
    emailScan.risk === 'Critical' ||
    emailScan.risk === 'High' ||
    (emailScan.risk === 'Medium' && emailScan.category !== 'Other');
  if (!suspiciousLink && !sandboxSuspicious && !emailSuspicious) {
    return null;
  }

  const topLinkScan = sandboxSuspicious || suspiciousLink?.result || linkAnalyses[0]?.result || null;
  const scanResult = buildAlertResult(subject, from, snippet, links, topLinkScan, emailScan);

  return {
    messageId: message.id,
    subject: subject || 'No subject',
    from: from || 'Unknown sender',
    detectedLinks: links,
    risk: scanResult.risk,
    category: scanResult.category,
    scanResult,
  };
};

export const runPreDeliveryMailboxScan = async (
  uid: string,
  email: string,
  accessToken: string,
  limit = 12,
): Promise<MailboxThreatScanSummary> => {
  const state = await getScanState(uid, email);
  const alreadyProcessed = new Set(state.processedMessageIds);
  const messageIds = await listRecentMessageIds(accessToken, Math.max(1, Math.min(limit, 30)));

  const freshIds = messageIds.filter((id) => !alreadyProcessed.has(id));
  const alerts: MailboxThreatFinding[] = [];

  for (const messageId of freshIds) {
    try {
      const message = await getMessage(accessToken, messageId);
      const finding = await evaluateMessageForThreat(message);
      if (finding) {
        alerts.push(finding);
      }
      alreadyProcessed.add(messageId);
    } catch {
      alreadyProcessed.add(messageId);
    }
  }

  await saveScanState(uid, email, {
    processedMessageIds: Array.from(alreadyProcessed).slice(-MAX_TRACKED_MESSAGE_IDS),
    lastScanAt: new Date().toISOString(),
  });

  return {
    scannedCount: freshIds.length,
    alertCount: alerts.length,
    alerts,
  };
};

export const persistMailboxThreatAlerts = async (uid: string, alerts: MailboxThreatFinding[]) => {
  for (const alert of alerts) {
    const input = `${alert.subject}\n${alert.from}\n${alert.detectedLinks.join('\n')}`.trim();
    await saveScanEvent(uid, input, 'email', alert.scanResult);
  }
};
