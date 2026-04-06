import type { ThreatCategory, RiskLevel } from './theme';

export interface AppUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
}

export type DetectionSensitivity = 'low' | 'medium' | 'high';

export interface UserPreferences {
  realtimeEnabled: boolean;
  detectionSensitivity: DetectionSensitivity;
  notifications: {
    criticalAlerts: boolean;
    weeklyReport: boolean;
    marketing: boolean;
  };
}

export interface LinkedEmail {
  email: string;
  linkedAt: string;
  lastSyncedAt?: string;
  hasCompletedInitialScan?: boolean;
  status: 'active' | 'syncing' | 'error';
  provider?: 'manual' | 'gmail-oauth';
  health?: 'healthy' | 'watch' | 'degraded';
  lastAlertAt?: string;
  lastAlertCount?: number;
  lastScannedCount?: number;
  lastScanOutcome?: 'clean' | 'alerts' | 'failed';
  nextScheduledScanAt?: string;
  consecutiveFailures?: number;
  lastError?: string;
  topSignals?: string[];
  tokens?: Record<string, unknown>;
}

export interface ThreatAnalysis {
  summary: string;
  detailedSummary: string;
  confidence: number;
  recommendation: string;
  technicalDetails: { label: string; description: string }[];
  detectionMethod: string;
  impactScore: number;
  affectedAssets: string[];
  mitreTechnique: string;
  mitreTactic: string;
}

export interface Threat {
  id: string;
  source: string;
  type: string;
  category: ThreatCategory;
  risk: RiskLevel;
  timestamp: string;
  aiAnalysis: ThreatAnalysis;
  status?: 'active' | 'reviewed';
}

export interface ScanTechnicalDetail {
  label: string;
  description: string;
}

export interface ScanResult {
  summary: string;
  detailedSummary: string;
  confidence: number;
  recommendation: string;
  risk: RiskLevel;
  category: ThreatCategory;
  impactScore: number;
  mitreTechnique: string;
  mitreTactic: string;
  technicalDetails: ScanTechnicalDetail[];
  analysisSource: 'backend-model' | 'gemini' | 'hybrid' | 'local-intelligence' | 'fallback';
  analysisSourceLabel: string;
}

export interface EmailFeatureSnapshot {
  numLinks: number;
  hasIpUrl: boolean;
  numSuspiciousWords: number;
  numExclamations: number;
  emailLength: number;
  numDigits: number;
  hasHtml: boolean;
}

export interface EmailDetectionResponse {
  label: 'phishing' | 'legitimate';
  confidence: number;
  phishingProbability?: number;
  phishing_probability?: number;
  features?: Partial<EmailFeatureSnapshot>;
  model?: string;
}

export interface ScanEvent {
  id: string;
  inputType: 'url' | 'email';
  inputPreview: string;
  createdAt: string;
  risk: RiskLevel;
  category: ThreatCategory;
  confidence: number;
  summary: string;
  recommendation: string;
  analysisSource: ScanResult['analysisSource'];
  analysisSourceLabel: string;
  mitreTechnique: string;
  mitreTactic: string;
  action: 'Blocked' | 'Allowed' | 'Review';
  threatId?: string;
}
