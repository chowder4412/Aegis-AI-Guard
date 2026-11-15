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
      <View style={styles.headerDeck}>
        <View style={styles.headerLeft}>
          <Text style={[styles.title, isMobile && styles.titleMobile]}>
            Threat <Text style={{ color: palette.secondary }}>Scanner</Text>
          </Text>
        </View>
        <View style={styles.hudPillRow}>
          <View style={[styles.hudPill, phishingApiConfigured ? styles.hudPillSuccess : styles.hudPillWarn]}>
            <View style={[styles.pillDot, { backgroundColor: phishingApiConfigured ? palette.secondary : palette.error }]} />
            <Text style={styles.hudPillText}>{phishingApiConfigured ? 'API Online' : 'API Offline'}</Text>
          </View>
          <View style={[styles.hudPill, styles.hudPillSuccess]}>
            <View style={[styles.pillDot, { backgroundColor: palette.secondary }]} />
            <Text style={styles.hudPillText}>Heuristics Active</Text>
          </View>
          <View style={[styles.hudPill, geminiConfigured ? styles.hudPillSuccess : styles.hudPillNeutral]}>
            <View style={[styles.pillDot, { backgroundColor: geminiConfigured ? palette.secondary : palette.primaryMuted }]} />
            <Text style={styles.hudPillText}>{geminiConfigured ? 'Copilot Ready' : 'Copilot Standby'}</Text>
          </View>
        </View>
      </View>

      <View style={[styles.grid, isDesktop && styles.gridDesktop]}>
        <View style={[styles.mainCard, isMobile && styles.mainCardMobile, isDesktop && styles.mainCardDesktop]}>
          <ManualScan />
        </View>

        <View style={[styles.sideColumn, isDesktop && styles.sideColumnDesktop]}>
          <View style={styles.sideCard}>
            <Text style={[styles.sideTitle, isMobile && styles.sideTitleMobile]}>System Diagnostics</Text>
            <View style={styles.diagnosticsList}>
              {[
                {
                  label: 'Detector API',
                  status: phishingApiConfigured ? 'Online' : 'Offline',
                  color: phishingApiConfigured ? palette.secondary : palette.error,
                  icon: phishingApiConfigured ? CheckCircle2 : CloudOff,
                },
                {
                  label: 'Client Heuristics',
                  status: 'Active',
                  color: palette.secondary,
                  icon: CheckCircle2,
                },
                {
                  label: 'Dynamic Sandbox',
                  status: 'Armed',
                  color: palette.secondary,
                  icon: CheckCircle2,
                },
                {
                  label: 'Recent Source',
                  status: recentSource,
                  color: palette.primaryMuted,
                  icon: BarChart3,
                },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <View key={item.label} style={styles.diagnosticRow}>
                    <Icon color={item.color} size={16} />
                    <Text style={styles.diagnosticTitle}>{item.label}</Text>
                    <Text style={[styles.diagnosticStatus, { color: item.color }]}>{item.status}</Text>
                  </View>
                );
              })}
            </View>
          </View>

          <View style={styles.metricCard}>
            <View style={styles.metricHeader}>
              <View style={styles.metricTitleRow}>
                <BarChart3 color={palette.secondary} size={16} />
                <Text style={styles.metricLabel}>Blocked Threats</Text>
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
    gap: 20,
    width: '100%',
    maxWidth: 1320,
    alignSelf: 'center',
  },
  headerDeck: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: 12,
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  hudPillRow: {
    flexDirection: 'row',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 8,
  },
  hudPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 999,
    borderWidth: 1,
  },
  hudPillSuccess: {
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderColor: 'rgba(74,225,131,0.22)',
  },
  hudPillWarn: {
    backgroundColor: 'rgba(255,107,107,0.08)',
    borderColor: 'rgba(255,107,107,0.22)',
  },
  hudPillNeutral: {
    backgroundColor: 'rgba(196,198,204,0.08)',
    borderColor: 'rgba(196,198,204,0.18)',
  },
  hudPillText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  pillDot: {
    width: 6,
    height: 6,
    borderRadius: 999,
  },
  title: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 36,
    lineHeight: 40,
  },
  titleMobile: {
    fontSize: 28,
    lineHeight: 32,
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
    gap: 10,
    alignItems: 'center',
  },
  diagnosticTitle: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
    flex: 1,
  },
  diagnosticStatus: {
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
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
