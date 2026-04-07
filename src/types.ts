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

export type AcademyAudience = 'beginner' | 'professional' | 'analyst';
export type AcademyDifficulty = 'Foundational' | 'Intermediate' | 'Advanced';
export type AcademyUrgency = 'Watch' | 'Elevated' | 'Critical';
export type AcademyPriority = 'High' | 'Medium';

export interface AcademyTrack {
  id: string;
  title: string;
  summary: string;
  focus: string;
  audience: AcademyAudience;
}

export interface AcademyLesson {
  id: string;
  title: string;
  summary: string;
  body: string;
  category: ThreatCategory;
  difficulty: AcademyDifficulty;
  audience: AcademyAudience;
  estimatedMinutes: number;
  practicePrompt: string;
  researchSource: string;
}

export interface ResearchBrief {
  id: string;
  title: string;
  summary: string;
  threatFamily: string;
  urgency: AcademyUrgency;
  source: string;
  action: string;
}

export interface RecommendedLesson {
  lessonId: string;
  priority: AcademyPriority;
  reason: string;
  signal: string;
}

export interface PracticeScenario {
  id: string;
  title: string;
  summary: string;
  inputType: 'url' | 'email';
  draftInput: string;
  lessonId: string;
  sourceLabel: string;
  riskLevel: RiskLevel;
}

export interface ScannerCoachingInsight {
  eyebrow: string;
  title: string;
  body: string;
  actionLabel: string;
}

export interface AcademyStats {
  researchBriefCount: number;
  linkedMailboxCount: number;
  highRiskFindings: number;
  recommendedLessonCount: number;
}

export interface EducationSnapshot {
  tracks: AcademyTrack[];
  lessons: AcademyLesson[];
  researchBriefs: ResearchBrief[];
  recommendedLessons: RecommendedLesson[];
  practiceScenarios: PracticeScenario[];
  stats: AcademyStats;
}

export interface LearningFeedbackSignal {
  kind: 'lesson' | 'scenario' | 'analysis-source' | 'indicator' | 'risk' | 'mailbox';
  value: string;
}

export interface LearningFeedbackPayload {
  content: string;
  inputType: 'url' | 'email';
  source: 'manual-scan' | 'academy-drill' | 'mailbox-scan';
  feedbackKind?: 'observation' | 'user-correction';
  risk: RiskLevel;
  category: ThreatCategory;
  confidence: number;
  summary: string;
  recommendation: string;
  analysisSource: ScanResult['analysisSource'];
  analysisSourceLabel: string;
  lessonId?: string | null;
  scenarioId?: string | null;
  scenarioTitle?: string | null;
  userLabel?: 'phishing' | 'legitimate' | 'unknown';
  signals?: LearningFeedbackSignal[];
}

export interface LearningFeedbackResponse {
  status: 'queued';
  queuedAt: string;
  continuousLearningEnabled: boolean;
}
