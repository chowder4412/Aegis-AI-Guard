import AsyncStorage from '@react-native-async-storage/async-storage';
import Constants from 'expo-constants';
import { Platform } from 'react-native';
import type { EmailDetectionResponse, EmailFeatureSnapshot, ScanResult } from '../types';

export const PHISHING_API_URL_STORAGE_KEY = 'aegis.phishing.apiUrl';
export type PhishingApiUrlSource = 'manual' | 'shared-env' | 'expo-dev' | 'unconfigured';

export interface BackendEmailDetectionResult {
  detection: EmailDetectionResponse;
  scanResult: ScanResult;
}

export interface ResolvedPhishingApiConfig {
  url: string;
  source: PhishingApiUrlSource;
}

const SUSPICIOUS_WORDS = ['urgent', 'verify', 'login', 'password', 'bank', 'click'];

const countMatches = (value: string, pattern: RegExp) => value.match(pattern)?.length ?? 0;

const extractEmailFeatures = (content: string): EmailFeatureSnapshot => {
  const normalized = content.toLowerCase();
  const urlPattern = /https?:\/\/[^\s]+|www\.[^\s]+/gi;
  const ipUrlPattern = /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i;

  return {
    numLinks: countMatches(content, urlPattern),
    hasIpUrl: ipUrlPattern.test(content),
    numSuspiciousWords: SUSPICIOUS_WORDS.reduce(
      (total, word) => total + countMatches(normalized, new RegExp(`\\b${word}\\b`, 'g')),
      0,
    ),
    numExclamations: countMatches(content, /!/g),
    emailLength: content.length,
    numDigits: countMatches(content, /\d/g),
    hasHtml: /<[^>]+>/.test(content),
  };
};

export const getStoredPhishingApiUrl = async () => {
  const storedValue = await AsyncStorage.getItem(PHISHING_API_URL_STORAGE_KEY);
  return storedValue || process.env.EXPO_PUBLIC_PHISHING_API_URL || '';
};

export const setStoredPhishingApiUrl = async (value: string) => {
  const normalized = value.trim().replace(/\/$/, '');
  if (!normalized) {
    await AsyncStorage.removeItem(PHISHING_API_URL_STORAGE_KEY);
    return;
  }

  await AsyncStorage.setItem(PHISHING_API_URL_STORAGE_KEY, normalized);
};

const normalizeBaseUrl = (value: string) => value.trim().replace(/\/$/, '');

const getExpoDevelopmentBackendUrl = () => {
  if (!__DEV__) {
    return '';
  }

  const configuredHost = (process.env.EXPO_PUBLIC_PHISHING_API_HOST || '').trim();
  const configuredPort = (process.env.EXPO_PUBLIC_PHISHING_API_PORT || '').trim() || '8000';
  if (configuredHost) {
    return `http://${configuredHost}:${configuredPort}`;
  }

  if (Platform.OS === 'web') {
    return `http://localhost:${configuredPort}`;
  }

  const hostUri =
    Constants.expoConfig?.hostUri ||
    Constants.expoGoConfig?.debuggerHost ||
    Constants.platform?.hostUri ||
    '';

  const hostname = String(hostUri).split(':')[0]?.trim();
  if (!hostname) {
    return '';
  }

  return `http://${hostname}:${configuredPort}`;
};

export const getResolvedPhishingApiConfig = async (): Promise<ResolvedPhishingApiConfig> => {
  const manualOrEnv = normalizeBaseUrl(await getStoredPhishingApiUrl());
  if (manualOrEnv) {
    const envValue = normalizeBaseUrl(process.env.EXPO_PUBLIC_PHISHING_API_URL || '');
    return {
      url: manualOrEnv,
      source: manualOrEnv === envValue ? 'shared-env' : 'manual',
    };
  }

  const expoDevUrl = normalizeBaseUrl(getExpoDevelopmentBackendUrl());
  if (expoDevUrl) {
    return {
      url: expoDevUrl,
      source: 'expo-dev',
    };
  }

  return {
    url: '',
    source: 'unconfigured',
  };
};

const getDetectEndpoint = async () => {
  const configured = normalizeBaseUrl((await getResolvedPhishingApiConfig()).url);
  if (!configured) {
    return '';
  }

  return configured.endsWith('/detect') ? configured : `${configured.replace(/\/$/, '')}/detect`;
};

const normalizeBackendPayload = (payload: unknown): EmailDetectionResponse | null => {
  if (!payload || typeof payload !== 'object') {
    return null;
  }

  const record = payload as Record<string, unknown>;
  const label = record.label;
  const confidence = record.confidence;

  if ((label !== 'phishing' && label !== 'legitimate') || !Number.isFinite(confidence)) {
    return null;
  }

  const normalized: EmailDetectionResponse = {
    label,
    confidence: Number(confidence),
  };

  const model = record.model;
  if (typeof model === 'string' && model.trim()) {
    normalized.model = model.trim();
  }

  const snakeProbability = record.phishing_probability;
  if (Number.isFinite(snakeProbability)) {
    normalized.phishing_probability = Number(snakeProbability);
    normalized.phishingProbability = Number(snakeProbability);
  }

  const camelProbability = record.phishingProbability;
  if (Number.isFinite(camelProbability)) {
    normalized.phishingProbability = Number(camelProbability);
  }

  if (record.features && typeof record.features === 'object') {
    normalized.features = record.features as Partial<EmailFeatureSnapshot>;
  }

  return normalized;
};

const normalizeConfidence = (value: number) => {
  if (!Number.isFinite(value)) {
    return 0;
  }

  if (value <= 1) {
    return Math.round(value * 100);
  }

  return Math.round(value);
};

const mapRisk = (label: EmailDetectionResponse['label'], confidence: number): ScanResult['risk'] => {
  if (label === 'phishing') {
    if (confidence >= 90) {
      return 'Critical';
    }
    if (confidence >= 75) {
      return 'High';
    }
    return 'Medium';
  }

  if (confidence >= 85) {
    return 'Low';
  }

  return 'Medium';
};

const buildTechnicalDetails = (features: EmailFeatureSnapshot): ScanResult['technicalDetails'] => {
  const details: ScanResult['technicalDetails'] = [];

  if (features.numLinks > 0) {
    details.push({
      label: 'Embedded links',
      description: `Detected ${features.numLinks} link${features.numLinks === 1 ? '' : 's'} in the email body.`,
    });
  }

  if (features.hasIpUrl) {
    details.push({
      label: 'IP-based URL',
      description: 'A destination URL uses a raw IP address, which is a common phishing signal.',
    });
  }

  if (features.numSuspiciousWords > 0) {
    details.push({
      label: 'Suspicious wording',
      description: `Matched ${features.numSuspiciousWords} urgency or credential-related keyword${features.numSuspiciousWords === 1 ? '' : 's'}.`,
    });
  }

  if (features.hasHtml) {
    details.push({
      label: 'HTML content',
      description: 'HTML markup was detected, which can hide links or spoofed branding.',
    });
  }

  if (details.length === 0) {
    details.push({
      label: 'Low-signal content',
      description: 'The message contains fewer obvious phishing features and was scored mostly from overall structure.',
    });
  }

  details.push({
    label: 'Feature vector',
    description: `Length ${features.emailLength}, digits ${features.numDigits}, exclamations ${features.numExclamations}.`,
  });

  return details.slice(0, 4);
};

const probabilityFromPayload = (payload: EmailDetectionResponse): number | null => {
  const candidate = payload.phishingProbability ?? payload.phishing_probability;
  if (candidate === undefined || !Number.isFinite(candidate)) {
    return null;
  }

  if (candidate > 1) {
    return Math.max(0, Math.min(1, Number(candidate) / 100));
  }

  return Math.max(0, Math.min(1, Number(candidate)));
};

const buildRecommendation = (label: EmailDetectionResponse['label']) =>
  label === 'phishing'
    ? 'Quarantine the message, block matching indicators, and warn impacted users before any interaction.'
    : 'Treat the message as lower risk, but review the sender and linked destinations before approval.';

const buildDetailedSummary = (label: EmailDetectionResponse['label'], confidence: number, modelName: string) =>
  label === 'phishing'
    ? `The backend phishing detector classified this email as phishing with ${confidence}% confidence using ${modelName}.`
    : `The backend phishing detector classified this email as legitimate with ${confidence}% confidence using ${modelName}.`;

const buildMitre = (label: EmailDetectionResponse['label']) =>
  label === 'phishing'
    ? { technique: 'T1566.002', tactic: 'Initial Access' }
    : { technique: 'T1583.001', tactic: 'Resource Development' };

const toScanResult = (content: string, payload: EmailDetectionResponse): ScanResult => {
  const confidence = normalizeConfidence(payload.confidence);
  const features = {
    ...extractEmailFeatures(content),
    ...payload.features,
  };
  const modelName = payload.model || 'Decision Tree API';
  const risk = mapRisk(payload.label, confidence);
  const mitre = buildMitre(payload.label);

  const probability = probabilityFromPayload(payload);

  const result: ScanResult = {
    summary:
      payload.label === 'phishing'
        ? 'The email matches phishing-oriented signals and should be treated as suspicious.'
        : 'The email looks more legitimate, but still benefits from analyst review.',
    detailedSummary: buildDetailedSummary(payload.label, confidence, modelName),
    confidence,
    recommendation: buildRecommendation(payload.label),
    risk,
    category: payload.label === 'phishing' ? 'Phishing' : 'Other',
    impactScore: Number(((confidence / 100) * (payload.label === 'phishing' ? 9.5 : 4.5)).toFixed(1)),
    mitreTechnique: mitre.technique,
    mitreTactic: mitre.tactic,
    technicalDetails: buildTechnicalDetails(features),
    analysisSource: 'backend-model',
    analysisSourceLabel: modelName,
  };

  if (probability !== null) {
    result.technicalDetails = [
      {
        label: 'Model probability',
        description: `Phishing probability score: ${Math.round(probability * 100)}%. Decision threshold is enforced on the backend.`,
      },
      ...result.technicalDetails,
    ].slice(0, 5);
  }

  return result;
};

export const detectEmailWithBackendDetailed = async (content: string): Promise<BackendEmailDetectionResult | null> => {
  const endpoint = await getDetectEndpoint();
  if (!endpoint) {
    return null;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content }),
      signal: controller.signal,
    });

    if (!response.ok) {
      return null;
    }

    const payload = normalizeBackendPayload(await response.json());
    if (!payload) {
      return null;
    }

    return {
      detection: payload,
      scanResult: toScanResult(content, payload),
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
};

export const detectEmailWithBackend = async (content: string): Promise<ScanResult | null> => {
  const result = await detectEmailWithBackendDetailed(content);
  return result?.scanResult ?? null;
};
