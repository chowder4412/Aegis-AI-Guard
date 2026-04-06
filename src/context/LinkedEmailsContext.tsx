import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Alert, Linking } from 'react-native';
import type { LinkedEmail } from '../types';
import { useAuth } from './AuthContext';
import { deleteBackendGmailMailboxSession, runBackendGmailMailboxScan } from '../services/backendMailboxService';
import { buildGmailOAuthStartUrl, parseGmailOAuthCallback } from '../services/gmailOAuthService';
import { removeStoredGmailMailboxSession, syncStoredGmailMailbox } from '../services/gmailSyncService';
import { persistMailboxThreatAlerts, runPreDeliveryMailboxScan } from '../services/gmailThreatShieldService';
import {
  removeLinkedEmailRecord,
  saveScanEvent,
  setLinkedEmailStatus,
  subscribeToLinkedEmails,
  upsertOAuthLinkedEmail,
} from '../services/securityDataService';

interface LinkedEmailsContextType {
  linkedEmails: LinkedEmail[];
  completeOAuthLink: (email: string) => Promise<void>;
  linkRealEmail: () => Promise<string>;
  scanLinkedMailboxes: () => Promise<{ scannedMailboxes: number; scannedMessages: number; alertCount: number }>;
  retryEmail: (email: string) => Promise<void>;
  removeEmail: (email: string) => Promise<void>;
  isAnyEmailLinked: boolean;
  loading: boolean;
  oauthStatus: 'idle' | 'processing' | 'success' | 'error';
  oauthMessage: string | null;
  clearOAuthMessage: () => void;
}

const LinkedEmailsContext = createContext<LinkedEmailsContextType | undefined>(undefined);

const buildCleanMailboxScanResult = (email: string, scannedCount: number) => ({
  summary: `Mailbox scan completed for ${email} with no high-risk threats detected.`,
  detailedSummary:
    scannedCount > 0
      ? `Aegis completed a live Gmail mailbox scan and reviewed the most recent ${scannedCount} email${scannedCount === 1 ? '' : 's'} without finding high-risk phishing indicators.`
      : `Aegis completed a live Gmail mailbox scan for ${email}, but no recent messages were available to inspect in this pass.`,
  confidence: scannedCount > 0 ? 92 : 74,
  recommendation:
    scannedCount > 0
      ? 'Keep Gmail protection connected and continue periodic rescans for new inbox activity.'
      : 'Keep Gmail protection connected and rescan after new messages arrive.',
  risk: 'Low' as const,
  category: 'Other' as const,
  impactScore: scannedCount > 0 ? 2.1 : 1.1,
  mitreTechnique: 'T1583.001',
  mitreTactic: 'Resource Development',
  technicalDetails: [
    {
      label: 'Mailbox coverage',
      description: `Scanned ${scannedCount} recent message${scannedCount === 1 ? '' : 's'} from the linked Gmail mailbox.`,
    },
    {
      label: 'Protection mode',
      description: 'Server-side Gmail sync and link inspection remained active during this scan.',
    },
  ],
  analysisSource: 'hybrid' as const,
  analysisSourceLabel: 'Mailbox Threat Shield',
});

const buildMailboxScanSummaryResult = (email: string, scannedCount: number, alertCount: number) => ({
  summary:
    alertCount > 0
      ? `Mailbox scan completed for ${email} and flagged suspicious inbox activity.`
      : `Mailbox scan completed for ${email} with no high-risk threats detected.`,
  detailedSummary:
    scannedCount > 0
      ? `Aegis reviewed ${scannedCount} recent email${scannedCount === 1 ? '' : 's'} from ${email} and recorded ${alertCount} suspicious finding${alertCount === 1 ? '' : 's'}.`
      : `Aegis completed a live Gmail mailbox scan for ${email}, but Gmail returned no recent inbox messages for this pass.`,
  confidence: scannedCount > 0 ? 90 : 72,
  recommendation:
    alertCount > 0
      ? 'Review the flagged mailbox alerts, quarantine suspicious messages, and continue rescanning for new inbox activity.'
      : 'Keep Gmail protection connected and continue periodic rescans for new inbox activity.',
  risk: 'Low' as const,
  category: 'Other' as const,
  impactScore: alertCount > 0 ? 3.2 : scannedCount > 0 ? 2.1 : 1.1,
  mitreTechnique: 'T1583.001',
  mitreTactic: 'Resource Development',
  technicalDetails: [
    {
      label: 'Mailbox coverage',
      description: `Scanned ${scannedCount} recent message${scannedCount === 1 ? '' : 's'} from the linked Gmail mailbox.`,
    },
    {
      label: 'Flagged findings',
      description: `${alertCount} suspicious email${alertCount === 1 ? '' : 's'} detected during this mailbox scan.`,
    },
    {
      label: 'Protection mode',
      description: 'Server-side Gmail sync and link inspection remained active during this scan.',
    },
  ],
  analysisSource: 'hybrid' as const,
  analysisSourceLabel: 'Mailbox Threat Shield',
});

const AUTO_SCAN_INTERVAL_MS = 60_000;
const DEFAULT_RETRY_DELAY_MS = 10 * 60_000;

const buildMailboxSuccessPatch = (
  summary: {
    lastSyncedAt: string;
    alertCount: number;
    scannedCount: number;
    nextScheduledScanAt: string;
    mailboxHealth: 'healthy' | 'watch' | 'degraded';
    consecutiveFailures: number;
    firstScanCompleted: boolean;
    topSignals: string[];
  },
  status: LinkedEmail['status'] = 'active',
): Partial<LinkedEmail> => ({
  status,
  lastSyncedAt: summary.lastSyncedAt,
  hasCompletedInitialScan: summary.firstScanCompleted,
  lastAlertAt: summary.alertCount > 0 ? summary.lastSyncedAt : '',
  lastAlertCount: summary.alertCount,
  lastScannedCount: summary.scannedCount,
  lastScanOutcome: summary.alertCount > 0 ? 'alerts' : 'clean',
  nextScheduledScanAt: summary.nextScheduledScanAt,
  health: summary.mailboxHealth,
  consecutiveFailures: summary.consecutiveFailures,
  lastError: '',
  topSignals: summary.topSignals,
});

const buildMailboxFailurePatch = (mailbox: LinkedEmail, error: unknown): Partial<LinkedEmail> => {
  const consecutiveFailures = (mailbox.consecutiveFailures || 0) + 1;
  const nextScheduledScanAt = new Date(Date.now() + Math.min(30, consecutiveFailures * 5) * 60_000).toISOString();
  return {
    status: 'error',
    health: 'degraded',
    consecutiveFailures,
    lastError: error instanceof Error ? error.message : 'Mailbox scan failed.',
    lastScanOutcome: 'failed',
    nextScheduledScanAt,
  };
};

const isMailboxDueForScan = (mailbox: LinkedEmail) => {
  if (!mailbox.nextScheduledScanAt) {
    return true;
  }

  const nextAt = Date.parse(mailbox.nextScheduledScanAt);
  return Number.isNaN(nextAt) || nextAt <= Date.now();
};

const buildTopSignals = (
  alerts: Array<{ scanResult: { summary: string; technicalDetails: { description: string }[] } }>,
  scannedCount: number,
) => {
  const signals: string[] = [];
  if (scannedCount === 0) {
    signals.push('No new inbox messages were available during this pass.');
  }
  for (const alert of alerts) {
    if (alert.scanResult.summary && !signals.includes(alert.scanResult.summary)) {
      signals.push(alert.scanResult.summary);
    }
    for (const detail of alert.scanResult.technicalDetails.slice(0, 2)) {
      if (detail.description && !signals.includes(detail.description)) {
        signals.push(detail.description);
      }
      if (signals.length >= 4) {
        break;
      }
    }
    if (signals.length >= 4) {
      break;
    }
  }
  if (signals.length === 0) {
    signals.push('Mailbox scan completed without high-risk findings.');
  }
  return signals.slice(0, 4);
};

export const LinkedEmailsProvider = ({ children }: { children: React.ReactNode }) => {
  const { user } = useAuth();
  const [linkedEmails, setLinkedEmails] = useState<LinkedEmail[]>([]);
  const [loading, setLoading] = useState(true);
  const [oauthStatus, setOauthStatus] = useState<'idle' | 'processing' | 'success' | 'error'>('idle');
  const [oauthMessage, setOauthMessage] = useState<string | null>(null);
  const autoScanRunningRef = useRef(false);

  const patchLocalMailbox = (email: string, updates: Partial<LinkedEmail>) => {
    const normalizedEmail = email.trim().toLowerCase();
    setLinkedEmails((current) =>
      current.map((item) => (item.email === normalizedEmail ? { ...item, ...updates } : item)),
    );
  };

  const runThreatShieldForMailbox = async (uid: string, email: string, provider: LinkedEmail['provider']) => {
    if (provider === 'gmail-oauth') {
      const summary = await runBackendGmailMailboxScan(email, 14);
      if (summary.alertCount > 0) {
        await persistMailboxThreatAlerts(uid, summary.alerts);
      }

      return {
        synced: {
          email: summary.email,
          session: {
            lastValidatedAt: summary.lastSyncedAt,
          },
        },
        summary,
      };
    }

    const synced = await syncStoredGmailMailbox(uid, email);
    const summary = await runPreDeliveryMailboxScan(uid, synced.email, synced.session.accessToken, 14);
    if (summary.alertCount > 0) {
      await persistMailboxThreatAlerts(uid, summary.alerts);
    }

    const lastSyncedAt = synced.session.lastValidatedAt;
    const mailboxHealth: 'healthy' | 'watch' | 'degraded' = summary.alertCount > 0 ? 'watch' : 'healthy';
    const nextScheduledScanAt = new Date(Date.now() + (summary.alertCount > 0 ? 5 : summary.scannedCount > 0 ? 10 : 20) * 60_000).toISOString();

    return {
      synced,
      summary: {
        ...summary,
        email: synced.email,
        lastSyncedAt,
        nextScheduledScanAt,
        mailboxHealth,
        consecutiveFailures: 0,
        firstScanCompleted: true,
        topSignals: buildTopSignals(summary.alerts, summary.scannedCount),
      },
    };
  };

  const finalizeOAuthMailboxLink = async (uid: string, email: string) => {
    const normalizedEmail = email.trim().toLowerCase();
    await upsertOAuthLinkedEmail(uid, normalizedEmail);

    await setLinkedEmailStatus(uid, normalizedEmail, { status: 'syncing' });
    try {
      const { synced, summary } = await runThreatShieldForMailbox(uid, normalizedEmail, 'gmail-oauth');
      const successPatch = buildMailboxSuccessPatch(summary);
      await setLinkedEmailStatus(uid, normalizedEmail, successPatch);
      patchLocalMailbox(normalizedEmail, successPatch);

      if (summary.alertCount > 0) {
        setOauthStatus('error');
        setOauthMessage(
          `${synced.email} connected. Threat shield flagged ${summary.alertCount} high-risk email${summary.alertCount === 1 ? '' : 's'} before inbox interaction.`,
        );
        Alert.alert(
          'Potential Scam Alert',
          `Threat shield detected ${summary.alertCount} suspicious email${summary.alertCount === 1 ? '' : 's'} containing risky links.`,
        );
      } else {
        setOauthStatus('success');
        setOauthMessage(`${synced.email} connected and scanned. No high-risk links detected.`);
      }
    } catch (error) {
      const failurePatch = buildMailboxFailurePatch({ email: normalizedEmail, linkedAt: '', status: 'error' }, error);
      await setLinkedEmailStatus(uid, normalizedEmail, failurePatch);
      patchLocalMailbox(normalizedEmail, failurePatch);
      const message = error instanceof Error ? error.message : 'Mailbox was linked but threat shield sync failed.';
      setOauthStatus('error');
      setOauthMessage(message);
      throw error;
    }
  };

  useEffect(() => {
    if (!user) {
      setLinkedEmails([]);
      setLoading(false);
      setOauthStatus('idle');
      setOauthMessage(null);
      return;
    }

    setLoading(true);
    const unsubscribe = subscribeToLinkedEmails(
      user.uid,
      (items) => {
        setLinkedEmails(items);
        setLoading(false);
      },
      () => {
        setLinkedEmails([]);
        setLoading(false);
      },
    );

    return unsubscribe;
  }, [user]);

  useEffect(() => {
    if (!user) {
      return;
    }

    const processCallbackUrl = async (url: string) => {
      const callback = parseGmailOAuthCallback(url);
      if (!callback) {
        return;
      }

      if (callback.status === 'error') {
        setOauthStatus('error');
        setOauthMessage(callback.error || 'OAuth mailbox linking failed.');
        return;
      }

      if (!callback.email) {
        setOauthStatus('error');
        setOauthMessage('OAuth completed without a mailbox address.');
        return;
      }

      setOauthStatus('processing');
      try {
        await finalizeOAuthMailboxLink(user.uid, callback.email);
      } catch (error) {
        setOauthStatus('error');
        setOauthMessage(error instanceof Error ? error.message : 'Unable to save the OAuth mailbox.');
      }
    };

    void Linking.getInitialURL().then((url) => {
      if (url) {
        void processCallbackUrl(url);
      }
    });

    const subscription = Linking.addEventListener('url', ({ url }) => {
      void processCallbackUrl(url);
    });

    return () => {
      subscription.remove();
    };
  }, [user]);

  useEffect(() => {
    if (!user) {
      return;
    }

    const activeOAuthMailboxes = linkedEmails.filter((item) => item.provider === 'gmail-oauth');

    if (activeOAuthMailboxes.length === 0) {
      return;
    }

    let cancelled = false;

    const runCycle = async () => {
      if (autoScanRunningRef.current) {
        return;
      }

      autoScanRunningRef.current = true;
      try {
        const dueMailboxes = activeOAuthMailboxes.filter(isMailboxDueForScan);
        if (dueMailboxes.length === 0) {
          return;
        }

        for (const mailbox of dueMailboxes) {
          if (cancelled) {
            break;
          }

          try {
            const { synced, summary } = await runThreatShieldForMailbox(user.uid, mailbox.email, mailbox.provider);
            const successPatch = buildMailboxSuccessPatch(summary);
            await setLinkedEmailStatus(user.uid, mailbox.email, successPatch);
            patchLocalMailbox(mailbox.email, successPatch);

            if (summary.alertCount > 0) {
              setOauthStatus('error');
              setOauthMessage(
                `${synced.email}: pre-delivery shield detected ${summary.alertCount} new suspicious email${summary.alertCount === 1 ? '' : 's'} with risky links.`,
              );
              Alert.alert(
                'Potential Scam Alert',
                `Threat shield detected ${summary.alertCount} new suspicious email${summary.alertCount === 1 ? '' : 's'} in ${synced.email}.`,
              );
            }
          } catch (error) {
            const failurePatch = buildMailboxFailurePatch(mailbox, error);
            await setLinkedEmailStatus(user.uid, mailbox.email, failurePatch);
            patchLocalMailbox(mailbox.email, failurePatch);
            // Keep polling other mailboxes even when one mailbox fails.
          }
        }
      } finally {
        autoScanRunningRef.current = false;
      }
    };

    void runCycle();
    const interval = setInterval(() => {
      void runCycle();
    }, AUTO_SCAN_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [linkedEmails, user]);

  const completeOAuthLink = async (email: string) => {
    if (!user) {
      throw new Error('Sign in before completing OAuth mailbox linking.');
    }
    await finalizeOAuthMailboxLink(user.uid, email);
  };

  const linkRealEmail = async () => {
    if (!user) {
      throw new Error('Sign in before starting OAuth mailbox linking.');
    }

    const startUrl = await buildGmailOAuthStartUrl(user.uid);
    if (!startUrl) {
      throw new Error('A Gmail OAuth connector is not configured for this deployment yet.');
    }

    setOauthStatus('processing');
    setOauthMessage('Waiting for Gmail OAuth completion...');
    return startUrl;
  };

  const scanLinkedMailboxes = async () => {
    if (!user) {
      throw new Error('Sign in before running a mailbox scan.');
    }

    const realtimeMailboxes = linkedEmails.filter((item) => item.provider === 'gmail-oauth');
    if (realtimeMailboxes.length === 0) {
      throw new Error('Connect Gmail securely before running a live mailbox scan.');
    }

    let scannedMailboxes = 0;
    let scannedMessages = 0;
    let alertCount = 0;
    const failures: string[] = [];

    for (const mailbox of realtimeMailboxes) {
      try {
        await setLinkedEmailStatus(user.uid, mailbox.email, { status: 'syncing' });
        const { synced, summary } = await runThreatShieldForMailbox(user.uid, mailbox.email, mailbox.provider);
        scannedMailboxes += 1;
        scannedMessages += summary.scannedCount;
        alertCount += summary.alertCount;

        const successPatch = buildMailboxSuccessPatch(summary);
        await setLinkedEmailStatus(user.uid, mailbox.email, successPatch);
        patchLocalMailbox(mailbox.email, successPatch);

        await saveScanEvent(
          user.uid,
          `${synced.email} mailbox scan (${summary.scannedCount} recent message${summary.scannedCount === 1 ? '' : 's'})`,
          'email',
          summary.alertCount === 0
            ? buildCleanMailboxScanResult(synced.email, summary.scannedCount)
            : buildMailboxScanSummaryResult(synced.email, summary.scannedCount, summary.alertCount),
        );
      } catch (error) {
        const failurePatch = buildMailboxFailurePatch(mailbox, error);
        await setLinkedEmailStatus(user.uid, mailbox.email, failurePatch);
        patchLocalMailbox(mailbox.email, failurePatch);
        failures.push(error instanceof Error ? `${mailbox.email}: ${error.message}` : mailbox.email);
      }
    }

    if (failures.length === realtimeMailboxes.length) {
      throw new Error(failures[0] || 'Unable to complete the mailbox scan.');
    }

    if (failures.length > 0) {
      setOauthStatus('error');
      setOauthMessage(`Mailbox scan completed with partial failures: ${failures.join(' | ')}`);
    } else if (alertCount > 0) {
      setOauthStatus('error');
      setOauthMessage(
        `Mailbox scan complete. Threat shield detected ${alertCount} suspicious email${alertCount === 1 ? '' : 's'} across ${scannedMailboxes} mailbox${scannedMailboxes === 1 ? '' : 'es'}.`,
      );
    } else {
      setOauthStatus('success');
      setOauthMessage(
        `Mailbox scan complete. Reviewed ${scannedMessages} recent email${scannedMessages === 1 ? '' : 's'} across ${scannedMailboxes} linked mailbox${scannedMailboxes === 1 ? '' : 'es'}.`,
      );
    }

    return {
      scannedMailboxes,
      scannedMessages,
      alertCount,
    };
  };

  const retryEmail = async (email: string) => {
    if (!user) {
      throw new Error('Sign in before retrying an email link.');
    }

    const linkedEmail = linkedEmails.find((item) => item.email === email.trim().toLowerCase());
    if (linkedEmail?.provider === 'gmail-oauth') {
      await setLinkedEmailStatus(user.uid, email, {
        status: 'syncing',
      });

      try {
        const { synced, summary } = await runThreatShieldForMailbox(user.uid, email, linkedEmail.provider);
        const successPatch = buildMailboxSuccessPatch(summary);
        await setLinkedEmailStatus(user.uid, email, successPatch);
        patchLocalMailbox(email, successPatch);
        if (summary.alertCount > 0) {
          setOauthStatus('error');
          setOauthMessage(
            `${synced.email} synced. Threat shield detected ${summary.alertCount} potential scam email${summary.alertCount === 1 ? '' : 's'} with suspicious links.`,
          );
          Alert.alert(
            'Potential Scam Alert',
            `Threat shield detected ${summary.alertCount} suspicious email${summary.alertCount === 1 ? '' : 's'} and logged it to your threat feed.`,
          );
        } else {
          setOauthStatus('success');
          setOauthMessage(`${synced.email} synced successfully. No high-risk links detected.`);
        }
      } catch (error) {
        const failurePatch = buildMailboxFailurePatch(linkedEmail, error);
        await setLinkedEmailStatus(user.uid, email, failurePatch);
        patchLocalMailbox(email, failurePatch);
        const message = error instanceof Error ? error.message : 'Unable to sync the Gmail mailbox.';
        setOauthStatus('error');
        setOauthMessage(message);
        throw error;
      }
      return;
    }

    await setLinkedEmailStatus(user.uid, email, {
      status: 'active',
      lastSyncedAt: new Date().toISOString(),
      nextScheduledScanAt: new Date(Date.now() + DEFAULT_RETRY_DELAY_MS).toISOString(),
    });
  };

  const removeEmail = async (email: string) => {
    if (!user) {
      throw new Error('Sign in before removing an email link.');
    }
    await removeStoredGmailMailboxSession(user.uid, email);
    await deleteBackendGmailMailboxSession(email);
    await removeLinkedEmailRecord(user.uid, email);
  };

  const clearOAuthMessage = () => {
    setOauthStatus('idle');
    setOauthMessage(null);
  };

  const isAnyEmailLinked = useMemo(
    () => linkedEmails.some((item) => item.provider === 'gmail-oauth' && item.status === 'active'),
    [linkedEmails],
  );

  return (
    <LinkedEmailsContext.Provider
      value={{
        linkedEmails,
        completeOAuthLink,
        linkRealEmail,
        scanLinkedMailboxes,
        retryEmail,
        removeEmail,
        isAnyEmailLinked,
        loading,
        oauthStatus,
        oauthMessage,
        clearOAuthMessage,
      }}
    >
      {children}
    </LinkedEmailsContext.Provider>
  );
};

export const useLinkedEmails = () => {
  const context = useContext(LinkedEmailsContext);
  if (!context) {
    throw new Error('useLinkedEmails must be used within a LinkedEmailsProvider');
  }
  return context;
};
