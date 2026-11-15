import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bolt,
  CheckCircle2,
  Copy,
  Globe,
  Mail,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  UserCheck,
  Zap,
} from 'lucide-react-native';
import { EmailLinker } from '../components/EmailLinker';
import { ThreatAnalytics } from '../components/ThreatAnalytics';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { analyzeContent } from '../services/geminiService';
import { getDefaultPreferences, saveScanEvent, subscribeToScanEvents, subscribeToThreats, subscribeToUserPreferences } from '../services/securityDataService';
import type { AppTab } from '../components/BottomNavBar';
import type { ScanEvent, ScanResult, Threat, UserPreferences } from '../types';
import { fonts, palette, riskColors, shadows } from '../theme';

interface DashboardProps {
  onNavigateTab?: (tab: AppTab) => void;
}

export const Dashboard = ({ onNavigateTab }: DashboardProps) => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { linkedEmails, scanLinkedMailboxes } = useLinkedEmails();
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [preferences, setPreferences] = useState<UserPreferences>(getDefaultPreferences());
  const [loading, setLoading] = useState(true);
  const [isMailboxScanning, setIsMailboxScanning] = useState(false);

  // Quick Ingestion Bar State
  const [quickInput, setQuickInput] = useState('');
  const [isQuickScanning, setIsQuickScanning] = useState(false);
  const [quickResult, setQuickResult] = useState<ScanResult | null>(null);

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

  const realtimeMailboxCount = useMemo(
    () => linkedEmails.filter((item) => item.provider === 'gmail-oauth' && item.status !== 'error').length,
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
    return realtimeMailboxes.length > 0 ? 'Active' : 'Standby';
  }, [linkedEmails]);

  const blockedCount = useMemo(() => scanEvents.filter((item) => item.action === 'Blocked').length, [scanEvents]);
  const blockedRate = scanEvents.length ? Math.round((blockedCount / scanEvents.length) * 100) : 0;

  const handleQuickPaste = async () => {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && text.trim()) {
        setQuickInput(text.trim());
      }
    } catch {
      // ignore
    }
  };

  const handleQuickScan = async () => {
    const trimmed = quickInput.trim();
    if (!trimmed) {
      return;
    }

    setIsQuickScanning(true);
    setQuickResult(null);
    try {
      const type = trimmed.includes('@') && !trimmed.startsWith('http') ? 'email' : 'url';
      const analysis = await analyzeContent(trimmed, type);
      setQuickResult(analysis);
      if (user) {
        await saveScanEvent(user.uid, trimmed, type, analysis);
      }
    } catch {
      Alert.alert('Scan Failed', 'Could not complete rapid security scan.');
    } finally {
      setIsQuickScanning(false);
    }
  };

  const handleMailboxSweep = async () => {
    if (realtimeMailboxCount === 0) {
      Alert.alert('Connect Mailbox', 'Link a Gmail mailbox below to run live background sweeps.');
      return;
    }

    setIsMailboxScanning(true);
    try {
      const summary = await scanLinkedMailboxes();
      Alert.alert(
        summary.alertCount > 0 ? 'Threats Detected' : 'Mailbox Sweep Clean',
        `Scanned ${summary.scannedMessages} messages across ${summary.scannedMailboxes} mailboxes. Detected ${summary.alertCount} threats.`,
      );
    } catch (error) {
      Alert.alert('Mailbox Sweep Failed', error instanceof Error ? error.message : 'Unable to complete sweep.');
    } finally {
      setIsMailboxScanning(false);
    }
  };

  return (
    <View style={styles.container}>
      {/* 1. Cockpit Header HUD & Quick Ingestion Bar */}
      <View style={styles.cockpitCard}>
        <View style={styles.cockpitTopRow}>
          <View style={styles.cockpitTitleBlock}>
            <View style={styles.statusPillActive}>
              <View style={styles.livePulseDot} />
              <Text style={styles.statusPillText}>PERIMETER ARMED</Text>
            </View>
            <Text style={[styles.cockpitTitle, isMobile && styles.cockpitTitleMobile]}>
              Cybersecurity <Text style={{ color: palette.secondary }}>Cockpit</Text>
            </Text>
          </View>

          <View style={styles.headerActionRow}>
            <Pressable
              disabled={isMailboxScanning}
              onPress={() => void handleMailboxSweep()}
              style={({ pressed }) => [styles.sweepButton, (pressed || isMailboxScanning) && styles.pressed]}
            >
              {isMailboxScanning ? <ActivityIndicator color="#14181F" size="small" /> : <Bolt color="#14181F" size={16} />}
              <Text style={styles.sweepButtonText}>{isMailboxScanning ? 'Sweeping...' : 'Run Mailbox Sweep'}</Text>
            </Pressable>
          </View>
        </View>

        {/* 1-Line Rapid Scan Bar */}
        <View style={styles.rapidBarWrap}>
          <Search color={palette.secondary} size={18} style={styles.rapidSearchIcon} />
          <TextInput
            onChangeText={setQuickInput}
            onSubmitEditing={() => void handleQuickScan()}
            placeholder="Rapid Ingestion: Paste URL or suspicious snippet for instant triage (Enter)..."
            placeholderTextColor="rgba(196,198,204,0.38)"
            returnKeyType="search"
            style={styles.rapidInput}
            value={quickInput}
          />
          <Pressable onPress={() => void handleQuickPaste()} style={styles.rapidPasteButton}>
            <Copy color={palette.secondary} size={12} />
            <Text style={styles.rapidPasteText}>Paste</Text>
          </Pressable>
          <Pressable
            disabled={isQuickScanning || !quickInput.trim()}
            onPress={() => void handleQuickScan()}
            style={({ pressed }) => [
              styles.rapidTriggerButton,
              (!quickInput.trim() || isQuickScanning || pressed) && styles.rapidTriggerDisabled,
            ]}
          >
            {isQuickScanning ? <ActivityIndicator color={palette.onSecondary} size="small" /> : <Zap color={palette.onSecondary} size={14} />}
            <Text style={styles.rapidTriggerText}>{isQuickScanning ? 'Scanning' : 'Triage'}</Text>
          </Pressable>
        </View>

        {/* Inline Rapid Scan Result (if triggered) */}
        {quickResult ? (
          <View style={styles.quickResultCard}>
            <View style={styles.quickResultHeader}>
              <View style={[styles.quickRiskBadge, { backgroundColor: riskColors[quickResult.risk].tint, borderColor: riskColors[quickResult.risk].text }]}>
                <View style={[styles.verdictDot, { backgroundColor: riskColors[quickResult.risk].text }]} />
                <Text style={[styles.quickRiskText, { color: riskColors[quickResult.risk].text }]}>
                  {quickResult.confidence}% {quickResult.risk.toUpperCase()} — {quickResult.category.toUpperCase()}
                </Text>
              </View>
              <Text style={styles.quickSourceText}>{quickResult.analysisSourceLabel}</Text>
            </View>
            <Text style={styles.quickSummaryText}>{quickResult.summary}</Text>
            {onNavigateTab ? (
              <Pressable onPress={() => onNavigateTab('scanner')} style={styles.openScannerLink}>
                <Text style={styles.openScannerLinkText}>Open in Full Scanner Deck</Text>
                <ArrowRight color={palette.secondary} size={14} />
              </Pressable>
            ) : null}
          </View>
        ) : null}
      </View>

      {/* 2. 4-Column Reactive Telemetry Grid */}
      <View style={[styles.telemetryGrid, isDesktop && styles.telemetryGridDesktop]}>
        <View style={styles.telemetryCard}>
          <Text style={styles.telemetryLabel}>SCANS PROCESSED</Text>
          <View style={styles.telemetryValueRow}>
            <Text style={styles.telemetryValue}>{scanEvents.length}</Text>
            <Text style={styles.telemetrySub}>Ingested</Text>
          </View>
          <View style={styles.telemetryTrack}>
            <View style={[styles.telemetryFill, { width: `${Math.min(scanEvents.length * 2, 100)}%` }]} />
          </View>
        </View>

        <View style={styles.telemetryCard}>
          <Text style={styles.telemetryLabel}>THREATS BLOCKED</Text>
          <View style={styles.telemetryValueRow}>
            <Text style={[styles.telemetryValue, { color: blockedCount > 0 ? palette.error : palette.secondary }]}>{blockedCount}</Text>
            <Text style={styles.telemetrySub}>{blockedRate}% Intercept</Text>
          </View>
          <View style={styles.telemetryTrack}>
            <View
              style={[
                styles.telemetryFill,
                { width: `${Math.max(blockedRate, 4)}%`, backgroundColor: blockedCount > 0 ? palette.error : palette.secondary },
              ]}
            />
          </View>
        </View>

        <View style={styles.telemetryCard}>
          <Text style={styles.telemetryLabel}>MAILBOX SYNC</Text>
          <View style={styles.telemetryValueRow}>
            <Text style={styles.telemetryValue}>{realtimeMailboxCount} Act</Text>
            <Text style={styles.telemetrySub}>{mailboxHealthLabel}</Text>
          </View>
          <View style={styles.telemetryTrack}>
            <View
              style={[
                styles.telemetryFill,
                {
                  width: realtimeMailboxCount > 0 ? '100%' : '12%',
                  backgroundColor: realtimeMailboxCount > 0 ? palette.success : palette.primaryMuted,
                },
              ]}
            />
          </View>
        </View>

        <View style={styles.telemetryCard}>
          <Text style={styles.telemetryLabel}>AVG INFERENCE</Text>
          <View style={styles.telemetryValueRow}>
            <Text style={styles.telemetryValue}>18ms</Text>
            <Text style={styles.telemetrySub}>FastAPI P95</Text>
          </View>
          <View style={styles.telemetryTrack}>
            <View style={[styles.telemetryFill, { width: '85%', backgroundColor: palette.secondary }]} />
          </View>
        </View>
      </View>

      {/* 3. Live Threat Stream (Chronological Intercepted Threats with MITRE Tags) */}
      <View style={styles.threatStreamBlock}>
        <View style={styles.threatStreamHeader}>
          <View style={styles.threatStreamTitleRow}>
            <ShieldAlert color={palette.error} size={20} />
            <Text style={styles.threatStreamTitle}>Live Threat Stream</Text>
          </View>
          <Text style={styles.threatStreamCount}>{threats.length} Intercepted</Text>
        </View>

        {loading ? (
          <View style={styles.threatLoadingBox}>
            <ActivityIndicator color={palette.secondary} size="small" />
            <Text style={styles.threatLoadingText}>Synchronizing live threat telemetry...</Text>
          </View>
        ) : threats.length === 0 ? (
          <View style={styles.emptyThreatBox}>
            <CheckCircle2 color={palette.secondary} size={24} />
            <Text style={styles.emptyThreatTitle}>No Active Hostile Exploits</Text>
            <Text style={styles.emptyThreatSub}>Perimeter integrity is intact. Real-time detonations and scan events stream here.</Text>
          </View>
        ) : (
          <View style={styles.threatCardList}>
            {threats.slice(0, 4).map((threat) => {
              const isHigh = threat.risk === 'Critical' || threat.risk === 'High';
              return (
                <View key={threat.id} style={styles.threatStreamCard}>
                  <View style={styles.threatCardLeft}>
                    <View style={[styles.threatSeverityBadge, { backgroundColor: isHigh ? 'rgba(255,107,107,0.12)' : 'rgba(255,183,77,0.12)' }]}>
                      <Text style={[styles.threatSeverityText, { color: isHigh ? palette.error : palette.warning }]}>
                        {threat.risk.toUpperCase()}
                      </Text>
                    </View>
                    <View style={styles.threatInfo}>
                      <Text style={styles.threatType}>{threat.type}</Text>
                      <Text numberOfLines={1} style={styles.threatSource}>
                        {threat.source}
                      </Text>
                    </View>
                  </View>

                  <View style={styles.threatCardRight}>
                    <View style={styles.mitreChip}>
                      <Text style={styles.mitreChipText}>MITRE T1566.001</Text>
                    </View>
                    <Text style={styles.threatTimestamp}>
                      {new Date(threat.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </Text>
                  </View>
                </View>
              );
            })}
          </View>
        )}
      </View>

      {/* 4. Threat Analytics & Email Integrations Deck */}
      <View style={[styles.deckGrid, isDesktop && styles.deckGridDesktop]}>
        <View style={styles.deckColumn}>
          <EmailLinker />
        </View>
        <View style={styles.deckColumn}>
          <ThreatAnalytics />
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
  cockpitCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.32)',
    padding: 24,
    gap: 18,
    ...shadows.card,
  },
  cockpitTopRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: 12,
  },
  cockpitTitleBlock: {
    gap: 6,
  },
  statusPillActive: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.22)',
    alignSelf: 'flex-start',
  },
  livePulseDot: {
    width: 6,
    height: 6,
    borderRadius: 999,
    backgroundColor: palette.secondary,
  },
  statusPillText: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.5,
  },
  cockpitTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 32,
    lineHeight: 36,
  },
  cockpitTitleMobile: {
    fontSize: 26,
    lineHeight: 30,
  },
  headerActionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  sweepButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 16,
    backgroundColor: palette.secondary,
  },
  sweepButtonText: {
    color: '#14181F',
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  rapidBarWrap: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(50,53,60,0.35)',
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.38)',
    paddingHorizontal: 14,
    paddingVertical: 6,
    gap: 8,
  },
  rapidSearchIcon: {
    marginLeft: 2,
  },
  rapidInput: {
    flex: 1,
    color: palette.onSurface,
    fontFamily: fonts.body,
    fontSize: 14,
    paddingVertical: 8,
  },
  rapidPasteButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 12,
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.2)',
  },
  rapidPasteText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 11,
  },
  rapidTriggerButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    backgroundColor: palette.secondary,
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 12,
  },
  rapidTriggerDisabled: {
    opacity: 0.65,
  },
  rapidTriggerText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  quickResultCard: {
    backgroundColor: 'rgba(20,27,33,0.85)',
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.2)',
    padding: 16,
    gap: 10,
  },
  quickResultHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: 8,
  },
  quickRiskBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 999,
    borderWidth: 1,
  },
  verdictDot: {
    width: 6,
    height: 6,
    borderRadius: 999,
  },
  quickRiskText: {
    fontFamily: fonts.headlineBold,
    fontSize: 11,
    letterSpacing: 1.2,
  },
  quickSourceText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  quickSummaryText: {
    color: palette.onSurface,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 20,
  },
  openScannerLink: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    alignSelf: 'flex-start',
    marginTop: 4,
  },
  openScannerLinkText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  telemetryGrid: {
    gap: 14,
  },
  telemetryGridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  telemetryCard: {
    flex: 1,
    backgroundColor: palette.surfaceLow,
    borderRadius: 22,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    padding: 18,
    gap: 10,
    ...shadows.card,
  },
  telemetryLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.5,
  },
  telemetryValueRow: {
    flexDirection: 'row',
    alignItems: 'baseline',
    justifyContent: 'space-between',
  },
  telemetryValue: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 26,
  },
  telemetrySub: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
  },
  telemetryTrack: {
    height: 6,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.3)',
    overflow: 'hidden',
  },
  telemetryFill: {
    height: '100%',
    backgroundColor: palette.secondary,
    borderRadius: 999,
  },
  threatStreamBlock: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 22,
    gap: 16,
    ...shadows.card,
  },
  threatStreamHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  threatStreamTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  threatStreamTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  threatStreamCount: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  threatLoadingBox: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    padding: 16,
  },
  threatLoadingText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
  },
  emptyThreatBox: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    gap: 8,
    borderRadius: 18,
    backgroundColor: 'rgba(74,225,131,0.04)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.14)',
  },
  emptyThreatTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 16,
  },
  emptyThreatSub: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    textAlign: 'center',
  },
  threatCardList: {
    gap: 10,
  },
  threatStreamCard: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: 'rgba(50,53,60,0.22)',
    borderRadius: 18,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    padding: 14,
    gap: 12,
  },
  threatCardLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    flex: 1,
  },
  threatSeverityBadge: {
    paddingHorizontal: 10,
    paddingVertical: 5,
    borderRadius: 10,
  },
  threatSeverityText: {
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.2,
  },
  threatInfo: {
    flex: 1,
    gap: 2,
  },
  threatType: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  threatSource: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
  },
  threatCardRight: {
    alignItems: 'flex-end',
    gap: 4,
  },
  mitreChip: {
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderColor: 'rgba(74,225,131,0.2)',
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 8,
    paddingVertical: 3,
  },
  mitreChipText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.2,
  },
  threatTimestamp: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 11,
  },
  deckGrid: {
    gap: 18,
  },
  deckGridDesktop: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  deckColumn: {
    flex: 1,
  },
  pressed: {
    opacity: 0.9,
    transform: [{ scale: 0.99 }],
  },
});
