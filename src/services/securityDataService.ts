import type { DetectionSensitivity, LinkedEmail, ScanEvent, ScanResult, Threat, UserPreferences } from '../types';
import { db, addDoc, collection, deleteDoc, doc, onSnapshot, orderBy, query, setDoc, updateDoc, limit } from '../firebase';

const DEFAULT_PREFERENCES: UserPreferences = {
  realtimeEnabled: true,
  detectionSensitivity: 'medium',
  notifications: {
    criticalAlerts: true,
    weeklyReport: true,
    marketing: false,
  },
};

const sanitizePreview = (value: string) => value.replace(/\s+/g, ' ').trim().slice(0, 120);

const shouldCreateThreat = (result: ScanResult) => result.risk !== 'Low' || result.category !== 'Other';

const toThreatType = (category: Threat['category']) => {
  switch (category) {
    case 'Malware':
      return 'Malware Distribution';
    case 'Spoofing':
      return 'Spoofing Attempt';
    case 'Social':
      return 'Social Engineering';
    case 'Phishing':
      return 'Phishing Attempt';
    case 'Other':
    default:
      return 'Suspicious Content';
  }
};

const toThreatSource = (inputType: 'url' | 'email', input: string) => {
  const preview = sanitizePreview(input);
  return inputType === 'url' ? preview : preview.slice(0, 80);
};

const userDoc = (uid: string) => doc(db, 'users', uid);
const linkedEmailsCollection = (uid: string) => collection(db, 'users', uid, 'linkedEmails');
const scanEventsCollection = (uid: string) => collection(db, 'users', uid, 'scanEvents');
const threatsCollection = (uid: string) => collection(db, 'users', uid, 'threats');

const buildLinkedMailboxDefaults = (now: string): Pick<
  LinkedEmail,
  | 'lastSyncedAt'
  | 'hasCompletedInitialScan'
  | 'status'
  | 'health'
  | 'lastAlertCount'
  | 'lastScannedCount'
  | 'lastScanOutcome'
  | 'nextScheduledScanAt'
  | 'consecutiveFailures'
  | 'topSignals'
> => ({
  lastSyncedAt: now,
  hasCompletedInitialScan: false,
  status: 'active',
  health: 'healthy',
  lastAlertCount: 0,
  lastScannedCount: 0,
  lastScanOutcome: 'clean',
  nextScheduledScanAt: now,
  consecutiveFailures: 0,
  topSignals: [],
});

export const getDefaultPreferences = () => DEFAULT_PREFERENCES;

export const subscribeToUserPreferences = (
  uid: string,
  onData: (preferences: UserPreferences) => void,
  onError?: () => void,
) =>
  onSnapshot(
    userDoc(uid),
    (snapshot) => {
      const data = snapshot.data() as { preferences?: Partial<UserPreferences> } | undefined;
      onData({
        ...DEFAULT_PREFERENCES,
        ...data?.preferences,
        notifications: {
          ...DEFAULT_PREFERENCES.notifications,
          ...data?.preferences?.notifications,
        },
      });
    },
    () => {
      onData(DEFAULT_PREFERENCES);
      onError?.();
    },
  );

export const saveUserPreferences = async (uid: string, preferences: Partial<UserPreferences>) => {
  const currentNotifications = preferences.notifications
    ? {
        ...DEFAULT_PREFERENCES.notifications,
        ...preferences.notifications,
      }
    : undefined;

  await setDoc(
    userDoc(uid),
    {
      preferences: {
        ...preferences,
        ...(currentNotifications ? { notifications: currentNotifications } : {}),
      },
      updatedAt: new Date().toISOString(),
    },
    { merge: true },
  );
};

export const subscribeToLinkedEmails = (
  uid: string,
  onData: (items: LinkedEmail[]) => void,
  onError?: () => void,
) =>
  onSnapshot(
    query(linkedEmailsCollection(uid), orderBy('linkedAt', 'desc')),
    (snapshot) => {
      onData(snapshot.docs.map((item) => item.data() as LinkedEmail));
    },
    () => {
      onData([]);
      onError?.();
    },
  );

export const upsertLinkedEmail = async (uid: string, email: string) => {
  const normalized = email.trim().toLowerCase();
  const now = new Date().toISOString();
  await setDoc(doc(db, 'users', uid, 'linkedEmails', encodeURIComponent(normalized)), {
    email: normalized,
    linkedAt: now,
    ...buildLinkedMailboxDefaults(now),
    provider: 'manual',
  } satisfies LinkedEmail);
};

export const upsertOAuthLinkedEmail = async (uid: string, email: string) => {
  const normalized = email.trim().toLowerCase();
  const now = new Date().toISOString();
  await setDoc(
    doc(db, 'users', uid, 'linkedEmails', encodeURIComponent(normalized)),
    {
      email: normalized,
      linkedAt: now,
      ...buildLinkedMailboxDefaults(now),
      provider: 'gmail-oauth',
    } satisfies LinkedEmail,
    { merge: true },
  );
};

export const removeLinkedEmailRecord = async (uid: string, email: string) => {
  await deleteDoc(doc(db, 'users', uid, 'linkedEmails', encodeURIComponent(email.trim().toLowerCase())));
};

export const retryLinkedEmailRecord = async (uid: string, email: string) => {
  await updateDoc(doc(db, 'users', uid, 'linkedEmails', encodeURIComponent(email.trim().toLowerCase())), {
    status: 'active',
    lastSyncedAt: new Date().toISOString(),
  });
};

export const setLinkedEmailStatus = async (uid: string, email: string, updates: Partial<LinkedEmail>) => {
  const sanitized = Object.fromEntries(Object.entries(updates).filter(([, value]) => value !== undefined));
  await updateDoc(doc(db, 'users', uid, 'linkedEmails', encodeURIComponent(email.trim().toLowerCase())), sanitized);
};

export const saveScanEvent = async (uid: string, input: string, inputType: 'url' | 'email', result: ScanResult) => {
  const createdAt = new Date().toISOString();
  const action: ScanEvent['action'] = result.risk === 'Low' ? 'Allowed' : result.risk === 'Medium' ? 'Review' : 'Blocked';

  let threatId: string | undefined;
  if (shouldCreateThreat(result)) {
    const threatRef = await addDoc(threatsCollection(uid), {
      source: toThreatSource(inputType, input),
      type: toThreatType(result.category),
      category: result.category,
      risk: result.risk,
      timestamp: createdAt,
      aiAnalysis: {
        summary: result.summary,
        detailedSummary: result.detailedSummary,
        confidence: result.confidence,
        recommendation: result.recommendation,
        technicalDetails: result.technicalDetails,
        detectionMethod: result.analysisSourceLabel,
        impactScore: result.impactScore,
        affectedAssets: inputType === 'email' ? ['Inbox', 'User Identity'] : ['Web Access', 'Endpoint Browser'],
        mitreTechnique: result.mitreTechnique,
        mitreTactic: result.mitreTactic,
      },
      status: 'active',
      inputType,
      createdAt,
    });
    threatId = threatRef.id;
  }

  await addDoc(scanEventsCollection(uid), {
    inputType,
    inputPreview: sanitizePreview(input),
    createdAt,
    risk: result.risk,
    category: result.category,
    confidence: result.confidence,
    summary: result.summary,
    recommendation: result.recommendation,
    analysisSource: result.analysisSource,
    analysisSourceLabel: result.analysisSourceLabel,
    mitreTechnique: result.mitreTechnique,
    mitreTactic: result.mitreTactic,
    action,
    threatId,
  } satisfies Omit<ScanEvent, 'id'>);
};

export const subscribeToThreats = (
  uid: string,
  onData: (items: Threat[]) => void,
  onError?: () => void,
  count = 20,
) =>
  onSnapshot(
    query(threatsCollection(uid), orderBy('timestamp', 'desc'), limit(count)),
    (snapshot) => {
      onData(snapshot.docs.map((item) => ({ ...(item.data() as Threat), id: item.id })));
    },
    () => {
      onData([]);
      onError?.();
    },
  );

export const subscribeToScanEvents = (
  uid: string,
  onData: (items: ScanEvent[]) => void,
  onError?: () => void,
  count = 50,
) =>
  onSnapshot(
    query(scanEventsCollection(uid), orderBy('createdAt', 'desc'), limit(count)),
    (snapshot) => {
      onData(snapshot.docs.map((item) => ({ ...(item.data() as Omit<ScanEvent, 'id'>), id: item.id })));
    },
    () => {
      onData([]);
      onError?.();
    },
  );

export const markThreatReviewed = async (uid: string, threatId: string) => {
  await updateDoc(doc(db, 'users', uid, 'threats', threatId), {
    status: 'reviewed',
  });
};

export const getProtectionGrade = (
  mailboxCount: number,
  realtimeEnabled: boolean,
  detectionSensitivity: DetectionSensitivity,
  criticalAlertsEnabled: boolean,
) => {
  let score = 58;
  score += Math.min(mailboxCount, 3) * 8;
  score += realtimeEnabled ? 14 : 0;
  score += detectionSensitivity === 'high' ? 12 : detectionSensitivity === 'medium' ? 8 : 4;
  score += criticalAlertsEnabled ? 8 : 0;
  const normalized = Math.min(score, 100);

  if (normalized >= 92) {
    return { grade: 'A', progress: normalized };
  }
  if (normalized >= 84) {
    return { grade: 'A-', progress: normalized };
  }
  if (normalized >= 76) {
    return { grade: 'B+', progress: normalized };
  }
  if (normalized >= 68) {
    return { grade: 'B', progress: normalized };
  }
  return { grade: 'C', progress: normalized };
};
