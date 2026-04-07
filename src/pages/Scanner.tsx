import { useEffect, useMemo, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import { BarChart3, BrainCircuit, CheckCircle2, CloudOff, RefreshCw, SearchCode } from 'lucide-react-native';
import { ManualScan } from '../components/ManualScan';
import { useAcademy } from '../context/AcademyContext';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { getScannerCoachingInsight } from '../services/educationService';
import { getStoredGeminiApiKey } from '../services/geminiService';
import { getResolvedPhishingApiConfig } from '../services/phishingApiService';
import { subscribeToScanEvents } from '../services/securityDataService';
import type { ScanEvent } from '../types';
import { fonts, palette, shadows } from '../theme';

export const Scanner = () => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { linkedEmails } = useLinkedEmails();
  const { activeScenario } = useAcademy();
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [phishingApiConfigured, setPhishingApiConfigured] = useState(false);
  const [phishingApiStatusLabel, setPhishingApiStatusLabel] = useState('No phishing detector endpoint configured');
  const [geminiConfigured, setGeminiConfigured] = useState(false);

  useEffect(() => {
    const hydrate = async () => {
      const [apiConfig, geminiKey] = await Promise.all([getResolvedPhishingApiConfig(), getStoredGeminiApiKey()]);
      setPhishingApiConfigured(Boolean(apiConfig.url.trim()));
      setPhishingApiStatusLabel(
        apiConfig.source === 'manual'
          ? 'Manual override active for backend-first email scoring'
          : apiConfig.source === 'shared-env'
            ? 'Shared app endpoint configured for backend-first email scoring'
            : apiConfig.source === 'expo-dev'
              ? 'Auto-detected local backend from current Expo dev host'
              : 'No phishing detector endpoint configured',
      );
      setGeminiConfigured(Boolean(geminiKey.trim()));
    };

    void hydrate();
  }, []);

  useEffect(() => {
    if (!user) {
      setEvents([]);
      return;
    }

    const unsubscribe = subscribeToScanEvents(user.uid, setEvents, () => setEvents([]), 50);
    return unsubscribe;
  }, [user]);

  const blockedCount = useMemo(() => events.filter((item) => item.action === 'Blocked').length, [events]);
  const recentSource = events[0]?.analysisSourceLabel || 'No scans yet';
  const coachingInsight = useMemo(
    () =>
      getScannerCoachingInsight({
        activeScenario,
        latestEvent: events[0],
        linkedMailboxCount: linkedEmails.filter((item) => item.provider === 'gmail-oauth').length,
      }),
    [activeScenario, events, linkedEmails],
  );

  return (
    <View style={styles.container}>
      <View>
        <Text style={[styles.title, isMobile && styles.titleMobile]}>
          Neural Phishing <Text style={{ color: palette.secondary }}>Analysis.</Text>
        </Text>
        <Text style={[styles.body, isMobile && styles.bodyMobile]}>
          Submit real URLs and email bodies into the detection pipeline. Results are saved to your workspace and drive the dashboard, logs, and threat analytics.
        </Text>
      </View>

      <View style={[styles.grid, isDesktop && styles.gridDesktop]}>
        <View style={[styles.mainCard, isMobile && styles.mainCardMobile, isDesktop && styles.mainCardDesktop]}>
          <View style={styles.backgroundIcon}>
            <SearchCode color="rgba(225,226,235,0.08)" size={120} />
          </View>
          <Text style={styles.eyebrow}>Security Ingestion Interface</Text>
          <View style={styles.coachingCard}>
            <View style={styles.coachingHeader}>
              <BrainCircuit color={palette.secondary} size={18} />
              <Text style={styles.coachingEyebrow}>{coachingInsight.eyebrow}</Text>
            </View>
            <Text style={styles.coachingTitle}>{coachingInsight.title}</Text>
            <Text style={styles.coachingBody}>{coachingInsight.body}</Text>
            <Text style={styles.coachingAction}>{coachingInsight.actionLabel}</Text>
          </View>
          <ManualScan />
        </View>

        <View style={[styles.sideColumn, isDesktop && styles.sideColumnDesktop]}>
          <View style={styles.sideCard}>
            <Text style={[styles.sideTitle, isMobile && styles.sideTitleMobile]}>Live Diagnostics</Text>
            <View style={styles.diagnosticsList}>
              {[
                {
                  label: 'Detector API',
                  sub: phishingApiStatusLabel,
                  icon: phishingApiConfigured ? CheckCircle2 : CloudOff,
                  color: phishingApiConfigured ? palette.secondary : palette.error,
                },
                {
                  label: 'Local Intelligence',
                  sub: 'Always active for on-device threat scoring and explainability',
                  icon: CheckCircle2,
                  color: palette.secondary,
                },
                {
                  label: 'Gemini Copilot',
                  sub: geminiConfigured ? 'Available as a copilot for URL scans and escalated email reviews' : 'No Gemini key detected for this session',
                  icon: geminiConfigured ? RefreshCw : CloudOff,
                  color: geminiConfigured ? palette.secondary : palette.primaryMuted,
                },
                {
                  label: 'Recent Source',
                  sub: recentSource,
                  icon: BarChart3,
                  color: palette.primaryMuted,
                },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <View key={item.label} style={styles.diagnosticRow}>
                    <Icon color={item.color} size={18} />
                    <View style={{ flex: 1 }}>
                      <Text style={styles.diagnosticTitle}>{item.label}</Text>
                      <Text style={styles.diagnosticBody}>{item.sub}</Text>
                    </View>
                  </View>
                );
              })}
            </View>
          </View>

          <View style={styles.metricCard}>
            <View style={styles.metricHeader}>
              <View style={styles.metricTitleRow}>
                <BarChart3 color={palette.primaryMuted} size={14} />
                <Text style={styles.metricLabel}>Blocked Findings</Text>
              </View>
              <Text style={styles.metricValue}>{blockedCount}</Text>
            </View>
            <View style={styles.metricTrack}>
              <View style={[styles.metricFill, { width: `${events.length ? Math.max((blockedCount / events.length) * 100, 8) : 8}%` }]} />
            </View>
          </View>
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    gap: 24,
    width: '100%',
    maxWidth: 1320,
    alignSelf: 'center',
  },
  title: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 48,
    lineHeight: 50,
  },
  titleMobile: {
    fontSize: 34,
    lineHeight: 38,
  },
  body: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 17,
    lineHeight: 25,
    marginTop: 12,
    maxWidth: 620,
  },
  bodyMobile: {
    fontSize: 15,
    lineHeight: 22,
    maxWidth: undefined,
  },
  grid: {
    gap: 18,
  },
  gridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  mainCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 36,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 20,
    overflow: 'hidden',
    ...shadows.card,
  },
  mainCardDesktop: {
    flex: 2,
  },
  mainCardMobile: {
    borderRadius: 30,
    padding: 20,
    gap: 18,
  },
  backgroundIcon: {
    position: 'absolute',
    top: 16,
    right: 16,
  },
  eyebrow: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  coachingCard: {
    borderRadius: 26,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.18)',
    backgroundColor: 'rgba(20,27,33,0.78)',
    padding: 18,
    gap: 8,
  },
  coachingHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  coachingEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  coachingTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 24,
    lineHeight: 28,
  },
  coachingBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  coachingAction: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  sideColumn: {
    gap: 18,
  },
  sideColumnDesktop: {
    flex: 1,
  },
  sideCard: {
    backgroundColor: 'rgba(50,53,60,0.26)',
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 18,
    ...shadows.card,
  },
  sideTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 28,
  },
  sideTitleMobile: {
    fontSize: 22,
  },
  diagnosticsList: {
    gap: 18,
  },
  diagnosticRow: {
    flexDirection: 'row',
    gap: 12,
    alignItems: 'flex-start',
  },
  diagnosticTitle: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 16,
  },
  diagnosticBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    marginTop: 4,
    lineHeight: 19,
  },
  metricCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 14,
    ...shadows.card,
  },
  metricHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  metricTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  metricLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  metricValue: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  metricTrack: {
    height: 8,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.28)',
    overflow: 'hidden',
  },
  metricFill: {
    height: '100%',
    backgroundColor: palette.secondary,
    borderRadius: 999,
  },
});
