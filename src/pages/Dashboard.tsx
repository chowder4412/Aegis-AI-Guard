import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, StyleSheet, Text, View } from 'react-native';
import { Activity, AtSign, Bolt, Mail, Shield, ShieldAlert, UserCheck } from 'lucide-react-native';
import { EmailLinker } from '../components/EmailLinker';
import { ManualScan } from '../components/ManualScan';
import { ThreatAnalytics } from '../components/ThreatAnalytics';
import { ThreatFeed } from '../components/ThreatFeed';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { getDefaultPreferences, subscribeToScanEvents, subscribeToThreats, subscribeToUserPreferences } from '../services/securityDataService';
import type { ScanEvent, Threat, UserPreferences } from '../types';
import { fonts, palette, shadows } from '../theme';

const countUniqueDays = (items: ScanEvent[]) => new Set(items.map((item) => item.createdAt.slice(0, 10))).size;

export const Dashboard = () => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { isAnyEmailLinked, linkedEmails, loading: linkedEmailsLoading, scanLinkedMailboxes } = useLinkedEmails();
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [preferences, setPreferences] = useState<UserPreferences>(getDefaultPreferences());
  const [loading, setLoading] = useState(true);
  const [isMailboxScanning, setIsMailboxScanning] = useState(false);
  const [hasTriggeredMailboxScan, setHasTriggeredMailboxScan] = useState(false);

  useEffect(() => {
    if (!user) {
      setScanEvents([]);
      setThreats([]);
      setPreferences(getDefaultPreferences());
      setLoading(false);
      return;
    }

    setLoading(true);
    const unsubscribeThreats = subscribeToThreats(
      user.uid,
      (items) => {
        setThreats(items);
        setLoading(false);
      },
      () => {
        setThreats([]);
        setLoading(false);
      },
      50,
    );
    const unsubscribeScans = subscribeToScanEvents(user.uid, setScanEvents, () => setScanEvents([]), 100);
    const unsubscribePreferences = subscribeToUserPreferences(user.uid, setPreferences);

    return () => {
      unsubscribeThreats();
      unsubscribeScans();
      unsubscribePreferences();
    };
  }, [user]);

  const stats = useMemo(() => {
    const blockedCount = scanEvents.filter((item) => item.action === 'Blocked').length;
    const averageConfidence = scanEvents.length
      ? Math.round(scanEvents.reduce((total, item) => total + item.confidence, 0) / scanEvents.length)
      : 0;
    const protectedDays = countUniqueDays(scanEvents);

    return [
      { label: 'Scans Processed', value: scanEvents.length.toString(), sub: 'Recorded' },
      { label: 'Blocked Detections', value: blockedCount.toString(), sub: scanEvents.length ? `${Math.round((blockedCount / scanEvents.length) * 100)}% rate` : '0% rate' },
      { label: 'Average Confidence', value: averageConfidence ? `${averageConfidence}%` : '0%', sub: protectedDays ? `${protectedDays} active days` : 'No activity' },
    ];
  }, [scanEvents]);

  const recentThreats = threats.slice(0, 3);
  const hasMailboxScanRecord = useMemo(
    () =>
      scanEvents.some(
        (item) =>
          item.inputType === 'email' &&
          (item.inputPreview.toLowerCase().includes('mailbox scan') || item.analysisSourceLabel === 'Mailbox Threat Shield'),
      ),
    [scanEvents],
  );
  const realtimeMailboxCount = useMemo(
    () => linkedEmails.filter((item) => item.provider === 'gmail-oauth' && item.status !== 'error').length,
    [linkedEmails],
  );
  const hasCompletedRealtimeScan = useMemo(
    () =>
      linkedEmails.some((item) => item.provider === 'gmail-oauth' && item.status !== 'error' && item.hasCompletedInitialScan),
    [linkedEmails],
  );
  const mailboxHealthLabel = useMemo(() => {
    const realtimeMailboxes = linkedEmails.filter((item) => item.provider === 'gmail-oauth');
    if (realtimeMailboxes.some((item) => item.health === 'degraded' || item.status === 'error')) {
      return 'Degraded';
    }
    if (realtimeMailboxes.some((item) => item.health === 'watch' || (item.lastAlertCount || 0) > 0)) {
      return 'Heightened Watch';
    }
    return realtimeMailboxes.length > 0 ? 'Healthy' : 'No mailbox linked';
  }, [linkedEmails]);
  const nextScheduledScanLabel = useMemo(() => {
    const nextTimes = linkedEmails
      .filter((item) => item.provider === 'gmail-oauth' && item.nextScheduledScanAt)
      .map((item) => Date.parse(item.nextScheduledScanAt!))
      .filter((value) => !Number.isNaN(value))
      .sort((left, right) => left - right);

    if (nextTimes.length === 0) {
      return realtimeMailboxCount > 0 ? 'Ready now' : 'Connect Gmail';
    }

    return new Date(nextTimes[0]).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }, [linkedEmails, realtimeMailboxCount]);
  const activeSignalSummary = useMemo(() => {
    const topSignals = linkedEmails
      .filter((item) => item.provider === 'gmail-oauth')
      .flatMap((item) => item.topSignals || [])
      .filter(Boolean);
    return topSignals[0] || 'No high-risk mailbox signals recorded in the latest cycle.';
  }, [linkedEmails]);

  useEffect(() => {
    if (hasCompletedRealtimeScan || hasMailboxScanRecord) {
      setHasTriggeredMailboxScan(true);
      return;
    }

    if (realtimeMailboxCount === 0) {
      setHasTriggeredMailboxScan(false);
    }
  }, [hasCompletedRealtimeScan, hasMailboxScanRecord, realtimeMailboxCount]);

  const protectionLine = useMemo(() => {
    if (!scanEvents.length) {
      return 'No completed scans yet';
    }
    return `${scanEvents.length} completed scans with ${threats.length} escalated threat record${threats.length === 1 ? '' : 's'}.`;
  }, [scanEvents.length, threats.length]);

  const heroBadgeLabel =
    realtimeMailboxCount > 0
      ? 'Protected Mailboxes Active'
      : 'Core Guard Active';

  const heroAccentColor =
    mailboxHealthLabel === 'Degraded'
      ? palette.error
      : mailboxHealthLabel === 'Heightened Watch'
        ? palette.secondary
        : realtimeMailboxCount > 0
          ? palette.success
          : palette.secondary;
  const heroBodyCopy =
    realtimeMailboxCount > 0
      ? 'This workspace is tied to authenticated Gmail mailbox records and persisted scan events. Threats, logs, and analytics are now driven from real inbox inspections.'
      : 'The workspace is active, but no authenticated Gmail mailboxes are linked yet. Manual scans still produce real audit logs and threat records.';
  const heroTitleAccent = realtimeMailboxCount > 0 ? 'protected.' : 'arming.';

  const heroButtonLabel = isMailboxScanning
    ? 'Scanning Emails...'
    : realtimeMailboxCount > 0
      ? hasTriggeredMailboxScan || hasCompletedRealtimeScan || hasMailboxScanRecord
        ? 'Scan Emails'
        : 'Ready for First Scan'
      : 'Connect Gmail to Scan';

  const handleMailboxScan = async () => {
    if (realtimeMailboxCount === 0) {
      Alert.alert('Realtime scan unavailable', 'Connect Gmail securely before running a live mailbox scan.');
      return;
    }

    setIsMailboxScanning(true);
    try {
      const summary = await scanLinkedMailboxes();
      setHasTriggeredMailboxScan(summary.scannedMailboxes > 0 || summary.scannedMessages >= 0);
      Alert.alert(
        summary.alertCount > 0 ? 'Threats detected' : 'Mailbox scan complete',
        summary.alertCount > 0
          ? `Threat shield detected ${summary.alertCount} suspicious email${summary.alertCount === 1 ? '' : 's'} while scanning ${summary.scannedMessages} recent message${summary.scannedMessages === 1 ? '' : 's'}.`
          : `Reviewed ${summary.scannedMessages} recent email${summary.scannedMessages === 1 ? '' : 's'} across ${summary.scannedMailboxes} mailbox${summary.scannedMailboxes === 1 ? '' : 'es'}.`,
      );
    } catch (error) {
      Alert.alert('Mailbox scan failed', error instanceof Error ? error.message : 'Unable to complete the live mailbox scan.');
    } finally {
      setIsMailboxScanning(false);
    }
  };

  return (
    <View style={styles.container}>
      <View style={[styles.heroGrid, isDesktop && styles.heroGridDesktop]}>
        <View style={[styles.heroCard, isMobile && styles.heroCardMobile, isDesktop && styles.heroCardDesktop]}>
          <View style={styles.heroHeader}>
            <View style={styles.heroBadge}>
              <UserCheck color={heroAccentColor} size={28} />
            </View>
            <Text style={[styles.heroBadgeText, { color: heroAccentColor }]}>{heroBadgeLabel}</Text>
          </View>

          <Text style={[styles.heroTitle, isMobile && styles.heroTitleMobile]}>
            Your digital perimeter is <Text style={{ color: heroAccentColor }}>{heroTitleAccent}</Text>
          </Text>
          <Text style={[styles.heroBody, isMobile && styles.heroBodyMobile]}>{heroBodyCopy}</Text>

          <Pressable
            onPress={() => void handleMailboxScan()}
            style={({ pressed }) => [styles.heroButton, (pressed || isMailboxScanning) && styles.pressed]}
          >
            {isMailboxScanning ? <ActivityIndicator color="#263046" size="small" /> : <Bolt color="#263046" size={18} />}
            <Text style={styles.heroButtonText}>{heroButtonLabel}</Text>
          </Pressable>

          <View style={styles.heroShieldWrap}>
            <Shield color={heroAccentColor} size={88} />
          </View>
        </View>

        <View style={[isDesktop && styles.emailLinkerDesktop]}>
          <EmailLinker />
        </View>
      </View>

      <View style={styles.sectionHeader}>
        <ShieldAlert color={palette.secondary} size={18} />
        <Text style={styles.sectionHeaderText}>Active Intelligence</Text>
      </View>

      <View style={[styles.intelligenceCard, isMobile && styles.intelligenceCardMobile, isDesktop && styles.intelligenceCardDesktop]}>
        <View style={[styles.intelligenceBlock, isDesktop && styles.intelligenceBlockDesktop]}>
          <Text style={[styles.blockTitle, isMobile && styles.blockTitleMobile]}>Operational Overview</Text>
          <Text style={styles.blockBody}>Live data pulled from stored scans, linked mailboxes, and threat escalations in Firestore.</Text>
          <View style={styles.infoGrid}>
            <View style={styles.infoCard}>
              <Text style={styles.infoLabel}>Mailbox Coverage</Text>
              <Text style={styles.infoValue}>{linkedEmailsLoading ? 'Loading...' : `${realtimeMailboxCount} protected`}</Text>
            </View>
            <View style={styles.infoCard}>
              <Text style={styles.infoLabel}>Mailbox Health</Text>
              <Text style={styles.infoValue}>{mailboxHealthLabel}</Text>
            </View>
            <View style={styles.infoCard}>
              <Text style={styles.infoLabel}>Next Sweep</Text>
              <Text style={styles.infoValue}>{nextScheduledScanLabel}</Text>
            </View>
            <View style={styles.infoCard}>
              <Text style={styles.infoLabel}>Active Signal</Text>
              <Text style={styles.infoValue}>{activeSignalSummary}</Text>
            </View>
          </View>
        </View>

        <View style={[styles.routeCard, isDesktop && styles.routeCardDesktop]}>
          <View style={styles.routeRow}>
            <View style={styles.routeNode}>
              <AtSign color={palette.secondary} size={16} />
              <Text style={styles.routeNodeLabel}>Input</Text>
            </View>
            <View style={styles.routeLine} />
            <View style={styles.routeNode}>
              <Mail color={palette.primary} size={16} />
              <Text style={styles.routeNodeLabel}>Model</Text>
            </View>
            <View style={styles.routeLine} />
            <View style={styles.routeNode}>
              <Activity color={palette.secondary} size={16} />
              <Text style={styles.routeNodeLabel}>Storage</Text>
            </View>
          </View>
          <Text style={styles.routeFooter}>
            {protectionLine} {realtimeMailboxCount > 0 ? `Next mailbox sweep at ${nextScheduledScanLabel}.` : ''}
          </Text>
        </View>
      </View>

      <ThreatFeed isLinked={isAnyEmailLinked} />

      <View style={[styles.statsGrid, isDesktop && styles.statsGridDesktop]}>
        {stats.map((stat) => (
          <View key={stat.label} style={[styles.statCard, isMobile && styles.statCardMobile, isDesktop && styles.statCardDesktop]}>
            <Text style={styles.statLabel}>{stat.label}</Text>
            <View style={styles.statRow}>
              <Text style={[styles.statValue, isMobile && styles.statValueMobile]}>{stat.value}</Text>
              <Text style={styles.statSub}>{stat.sub}</Text>
            </View>
          </View>
        ))}
      </View>

      <ThreatAnalytics />
      <ManualScan />

      <View style={styles.recentSectionHeader}>
        <View>
          <Text style={[styles.recentTitle, isMobile && styles.recentTitleMobile]}>Recent Threats</Text>
          <Text style={styles.recentBody}>Latest escalated detections created from stored scans in this workspace.</Text>
        </View>
      </View>

      <View style={styles.recentList}>
        {loading ? (
          <View style={styles.recentLoadingCard}>
            <ActivityIndicator color={palette.secondary} size="small" />
            <Text style={styles.recentBody}>Loading recent threat records...</Text>
          </View>
        ) : recentThreats.length === 0 ? (
          <View style={styles.recentLoadingCard}>
            <ShieldAlert color={palette.primaryMuted} size={28} />
            <Text style={styles.recentCardTitle}>No escalated threats yet</Text>
            <Text style={styles.recentCardBody}>High- and medium-risk detections appear here automatically after live scans are saved.</Text>
          </View>
        ) : (
          recentThreats.map((threat) => (
            <View key={threat.id} style={[styles.recentCard, isMobile && styles.recentCardMobile, isDesktop && styles.recentCardDesktop]}>
              <View style={styles.recentLeft}>
                <View style={styles.recentIcon}>
                  <ShieldAlert color={threat.risk === 'Critical' || threat.risk === 'High' ? palette.error : palette.primaryMuted} size={22} />
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.recentCardTitle}>{threat.type}</Text>
                  <Text style={styles.recentCardBody}>{threat.source}</Text>
                </View>
              </View>
              <View style={[styles.recentRight, isMobile && styles.recentRightMobile, isDesktop && styles.recentRightDesktop]}>
                <View style={[styles.recentRiskBadge, (threat.risk === 'Critical' || threat.risk === 'High') && styles.recentRiskBadgeHigh]}>
                  <Text style={[styles.recentRiskText, (threat.risk === 'Critical' || threat.risk === 'High') && styles.recentRiskTextHigh]}>{threat.risk}</Text>
                </View>
                <Text style={styles.reportButtonText}>{new Date(threat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</Text>
              </View>
            </View>
          ))
        )}
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
  heroGrid: {
    gap: 18,
  },
  heroGridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  heroCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 18,
    overflow: 'hidden',
    ...shadows.card,
  },
  heroCardDesktop: {
    flex: 2,
    minHeight: 320,
  },
  heroCardMobile: {
    borderRadius: 28,
    padding: 20,
    gap: 16,
  },
  emailLinkerDesktop: {
    flex: 1,
    minWidth: 380,
    maxWidth: 430,
  },
  heroHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  heroBadge: {
    width: 52,
    height: 52,
    borderRadius: 22,
    backgroundColor: 'rgba(74,225,131,0.08)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  heroBadgeText: {
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  heroTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 38,
    lineHeight: 42,
  },
  heroTitleMobile: {
    fontSize: 30,
    lineHeight: 34,
  },
  heroBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 16,
    lineHeight: 24,
    maxWidth: 520,
  },
  heroBodyMobile: {
    fontSize: 14,
    lineHeight: 21,
    maxWidth: undefined,
  },
  heroButton: {
    alignSelf: 'flex-start',
    borderRadius: 18,
    backgroundColor: palette.primary,
    paddingHorizontal: 18,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  heroButtonText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  heroShieldWrap: {
    position: 'absolute',
    right: -10,
    bottom: -10,
    opacity: 0.16,
  },
  sectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  sectionHeaderText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  intelligenceCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.12)',
    padding: 24,
    gap: 18,
    ...shadows.card,
  },
  intelligenceCardDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  intelligenceCardMobile: {
    borderRadius: 28,
    padding: 20,
  },
  intelligenceBlock: {
    gap: 14,
  },
  intelligenceBlockDesktop: {
    flex: 1,
  },
  blockTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 28,
  },
  blockTitleMobile: {
    fontSize: 24,
  },
  blockBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  infoGrid: {
    gap: 10,
  },
  infoCard: {
    borderRadius: 20,
    backgroundColor: 'rgba(50,53,60,0.24)',
    padding: 16,
    gap: 6,
  },
  infoLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  infoValue: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 16,
  },
  routeCard: {
    borderRadius: 28,
    backgroundColor: 'rgba(50,53,60,0.22)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    padding: 18,
    gap: 18,
  },
  routeCardDesktop: {
    width: 320,
    justifyContent: 'center',
  },
  routeRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 8,
  },
  routeNode: {
    alignItems: 'center',
    gap: 8,
    minWidth: 64,
  },
  routeNodeLabel: {
    color: palette.onSurface,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  routeLine: {
    flex: 1,
    height: 2,
    backgroundColor: palette.secondary,
    opacity: 0.5,
  },
  routeFooter: {
    color: palette.primaryMuted,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
    textAlign: 'center',
  },
  statsGrid: {
    gap: 12,
  },
  statsGridDesktop: {
    flexDirection: 'row',
  },
  statCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 20,
    ...shadows.card,
  },
  statCardDesktop: {
    flex: 1,
  },
  statCardMobile: {
    borderRadius: 24,
    padding: 18,
    gap: 16,
  },
  statLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  statRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: 10,
  },
  statValue: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 38,
  },
  statValueMobile: {
    fontSize: 32,
  },
  statSub: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
    marginBottom: 6,
  },
  recentSectionHeader: {
    gap: 6,
  },
  recentTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 30,
  },
  recentTitleMobile: {
    fontSize: 24,
  },
  recentBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
  },
  recentList: {
    gap: 12,
  },
  recentLoadingCard: {
    borderRadius: 28,
    backgroundColor: 'rgba(39,45,52,0.7)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.25)',
    padding: 22,
    gap: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  recentCard: {
    borderRadius: 28,
    backgroundColor: 'rgba(39,45,52,0.7)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.25)',
    padding: 18,
    gap: 14,
  },
  recentCardDesktop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  recentCardMobile: {
    borderRadius: 24,
    padding: 16,
  },
  recentLeft: {
    flexDirection: 'row',
    gap: 14,
  },
  recentIcon: {
    width: 52,
    height: 52,
    borderRadius: 20,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(50,53,60,0.26)',
  },
  recentCardTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 18,
    textAlign: 'center',
  },
  recentCardBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    marginTop: 6,
  },
  recentRight: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  recentRightDesktop: {
    minWidth: 250,
    justifyContent: 'flex-end',
  },
  recentRightMobile: {
    flexWrap: 'wrap',
    justifyContent: 'flex-start',
  },
  recentRiskBadge: {
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: 'rgba(187,198,226,0.16)',
  },
  recentRiskBadgeHigh: {
    backgroundColor: 'rgba(255,92,82,0.16)',
  },
  recentRiskText: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  recentRiskTextHigh: {
    color: palette.error,
  },
  reportButtonText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  pressed: {
    opacity: 0.92,
  },
});
