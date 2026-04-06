import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { ChevronLeft, ChevronRight, CloudOff, Link2Off, Mail, Search, ShieldAlert } from 'lucide-react-native';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import { subscribeToScanEvents } from '../services/securityDataService';
import type { ScanEvent } from '../types';
import { fonts, palette, riskColors, shadows } from '../theme';

const PAGE_SIZE = 8;
type FilterValue = 'All' | 'Phishing' | 'Spoofing' | 'Malware' | 'Other';

const getEventIcon = (event: ScanEvent) => {
  if (event.inputType === 'url') {
    return Link2Off;
  }
  if (event.category === 'Malware') {
    return CloudOff;
  }
  if (event.category === 'Phishing' || event.category === 'Spoofing') {
    return Mail;
  }
  return ShieldAlert;
};

export const Logs = () => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchValue, setSearchValue] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterValue>('All');
  const [page, setPage] = useState(0);

  useEffect(() => {
    if (!user) {
      setEvents([]);
      setLoading(false);
      return;
    }

    const unsubscribe = subscribeToScanEvents(
      user.uid,
      (items) => {
        setEvents(items);
        setLoading(false);
      },
      () => {
        setEvents([]);
        setLoading(false);
      },
      100,
    );

    return unsubscribe;
  }, [user]);

  useEffect(() => {
    setPage(0);
  }, [activeFilter, searchValue]);

  const filteredEvents = useMemo(() => {
    const normalizedSearch = searchValue.trim().toLowerCase();
    return events.filter((item) => {
      const matchesFilter = activeFilter === 'All' ? true : item.category === activeFilter;
      const matchesSearch = normalizedSearch
        ? [item.inputPreview, item.summary, item.analysisSourceLabel].some((value) => value.toLowerCase().includes(normalizedSearch))
        : true;
      return matchesFilter && matchesSearch;
    });
  }, [activeFilter, events, searchValue]);

  const totalPages = Math.max(Math.ceil(filteredEvents.length / PAGE_SIZE), 1);
  const visibleEvents = filteredEvents.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);

  const interceptedCount = filteredEvents.filter((item) => item.action === 'Blocked').length;

  return (
    <View style={styles.container}>
      <View style={[styles.header, isDesktop && styles.headerDesktop]}>
        <View style={{ flex: 1 }}>
          <Text style={styles.eyebrow}>Audit Intelligence</Text>
          <Text style={[styles.title, isMobile && styles.titleMobile]}>
            Threat <Text style={{ color: palette.primaryMuted }}>History.</Text>
          </Text>
          <Text style={[styles.body, isMobile && styles.bodyMobile]}>
            Live audit ledger for completed scans, mitigation actions, and high-risk detections stored in your secure workspace.
          </Text>
        </View>
        <View style={[styles.metricCard, isMobile && styles.metricCardMobile]}>
          <Text style={styles.metricLabel}>Total Intercepted</Text>
          <Text style={[styles.metricValue, isMobile && styles.metricValueMobile]}>{interceptedCount}</Text>
        </View>
      </View>

      <View style={[styles.topControls, isDesktop && styles.topControlsDesktop]}>
        <View style={[styles.filterCard, isDesktop && styles.filterCardDesktop]}>
          <Text style={styles.filterLabel}>Filter by</Text>
          <View style={styles.filterChips}>
            {(['All', 'Phishing', 'Spoofing', 'Malware', 'Other'] as FilterValue[]).map((item) => (
              <Pressable key={item} onPress={() => setActiveFilter(item)} style={[styles.filterChip, activeFilter === item && styles.filterChipActive]}>
                <Text style={[styles.filterChipText, activeFilter === item && styles.filterChipTextActive]}>{item}</Text>
              </Pressable>
            ))}
          </View>
          <View style={styles.searchWrap}>
            <Search color={palette.primaryMuted} size={14} />
            <TextInput
              onChangeText={setSearchValue}
              placeholder="Search logs..."
              placeholderTextColor="rgba(196,198,204,0.35)"
              style={styles.searchInput}
              value={searchValue}
            />
          </View>
        </View>

        <View style={[styles.statusCard, isDesktop && styles.statusCardDesktop]}>
          <Text style={styles.statusLabel}>System Status</Text>
          <View style={styles.statusRow}>
            <Text style={styles.statusValue}>{loading ? 'Syncing' : 'Audit Live'}</Text>
            <View style={[styles.statusDot, loading && styles.statusDotLoading]} />
          </View>
        </View>
      </View>

      <View style={styles.listCard}>
        {loading ? (
          <View style={styles.loadingState}>
            <ActivityIndicator color={palette.secondary} size="large" />
            <Text style={styles.paginationText}>Loading stored audit records...</Text>
          </View>
        ) : visibleEvents.length === 0 ? (
          <View style={styles.emptyState}>
            <ShieldAlert color={palette.primaryMuted} size={36} />
            <Text style={styles.emptyTitle}>No logs available</Text>
            <Text style={styles.emptyBody}>Run manual scans or create detections to populate the audit ledger.</Text>
          </View>
        ) : (
          visibleEvents.map((log) => {
            const Icon = getEventIcon(log);
            const blocked = log.action === 'Blocked';
            const riskStyle = riskColors[log.risk];
            return (
              <View key={log.id} style={styles.logRow}>
                <View style={styles.logMeta}>
                  <Text style={styles.logDate}>{new Date(log.createdAt).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}</Text>
                  <Text style={styles.logTime}>{new Date(log.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</Text>
                </View>

                <View style={styles.logVector}>
                  <Icon color={blocked ? palette.error : riskStyle.text} size={18} />
                  <Text style={styles.logType}>{log.category}</Text>
                </View>

                <Text style={styles.logSource}>{log.inputPreview}</Text>

                <View style={[styles.actionBadge, blocked && styles.actionBadgeBlocked, !blocked && { backgroundColor: riskStyle.tint }]}>
                  <Text style={[styles.actionText, blocked && styles.actionTextBlocked, !blocked && { color: riskStyle.text }]}>{log.action}</Text>
                </View>

                <Text style={styles.confidenceText}>{log.confidence}%</Text>
              </View>
            );
          })
        )}

        <View style={styles.pagination}>
          <Text style={styles.paginationText}>
            {filteredEvents.length === 0 ? 'No entries to show' : `Showing ${Math.min(page * PAGE_SIZE + visibleEvents.length, filteredEvents.length)} of ${filteredEvents.length} entries`}
          </Text>
          <View style={styles.paginationButtons}>
            <Pressable disabled={page === 0} onPress={() => setPage((current) => Math.max(current - 1, 0))} style={({ pressed }) => [styles.pageButton, (pressed || page === 0) && styles.pageButtonDisabled]}>
              <ChevronLeft color={palette.primaryMuted} size={18} />
            </Pressable>
            <Pressable
              disabled={page >= totalPages - 1}
              onPress={() => setPage((current) => Math.min(current + 1, totalPages - 1))}
              style={({ pressed }) => [styles.pageButton, (pressed || page >= totalPages - 1) && styles.pageButtonDisabled]}
            >
              <ChevronRight color={palette.primaryMuted} size={18} />
            </Pressable>
          </View>
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    gap: 18,
    width: '100%',
    maxWidth: 1320,
    alignSelf: 'center',
  },
  header: {
    gap: 18,
  },
  headerDesktop: {
    flexDirection: 'row',
    alignItems: 'flex-end',
  },
  topControls: {
    gap: 16,
  },
  topControlsDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  eyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  title: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 52,
    lineHeight: 54,
    marginTop: 12,
  },
  titleMobile: {
    fontSize: 38,
    lineHeight: 42,
  },
  body: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 17,
    lineHeight: 25,
    marginTop: 12,
  },
  bodyMobile: {
    fontSize: 15,
    lineHeight: 23,
  },
  metricCard: {
    alignSelf: 'flex-start',
    borderRadius: 28,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 8,
    ...shadows.card,
  },
  metricCardMobile: {
    borderRadius: 24,
    padding: 18,
  },
  metricLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  metricValue: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 38,
  },
  metricValueMobile: {
    fontSize: 30,
  },
  filterCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 18,
    gap: 14,
    ...shadows.card,
  },
  filterCardDesktop: {
    flex: 2,
  },
  filterLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  filterChips: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  filterChip: {
    borderRadius: 16,
    paddingHorizontal: 14,
    paddingVertical: 10,
    backgroundColor: palette.backgroundDeep,
  },
  filterChipActive: {
    backgroundColor: palette.surfaceHighest,
  },
  filterChipText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  filterChipTextActive: {
    color: palette.primary,
  },
  searchWrap: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    borderRadius: 16,
    backgroundColor: palette.backgroundDeep,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  searchInput: {
    flex: 1,
    color: palette.onSurface,
    fontFamily: fonts.body,
    fontSize: 14,
  },
  statusCard: {
    borderRadius: 28,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 10,
    ...shadows.card,
  },
  statusCardDesktop: {
    flex: 1,
    justifyContent: 'center',
  },
  statusLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  statusValue: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  statusDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
    backgroundColor: palette.secondary,
  },
  statusDotLoading: {
    backgroundColor: palette.warning,
  },
  listCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 18,
    gap: 14,
    ...shadows.card,
  },
  loadingState: {
    minHeight: 260,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 14,
  },
  emptyState: {
    minHeight: 260,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    paddingHorizontal: 24,
  },
  emptyTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 22,
  },
  emptyBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
    textAlign: 'center',
  },
  logRow: {
    borderRadius: 20,
    backgroundColor: 'rgba(50,53,60,0.24)',
    padding: 16,
    gap: 10,
  },
  logMeta: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  logDate: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  logTime: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 12,
  },
  logVector: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  logType: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
  },
  logSource: {
    color: palette.primary,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
  },
  actionBadge: {
    alignSelf: 'flex-start',
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  actionBadgeBlocked: {
    backgroundColor: 'rgba(255,92,82,0.16)',
  },
  actionText: {
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  actionTextBlocked: {
    color: palette.error,
  },
  confidenceText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  pagination: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: 6,
  },
  paginationText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  paginationButtons: {
    flexDirection: 'row',
    gap: 10,
  },
  pageButton: {
    width: 42,
    height: 42,
    borderRadius: 16,
    backgroundColor: palette.surfaceHighest,
    alignItems: 'center',
    justifyContent: 'center',
  },
  pageButtonDisabled: {
    opacity: 0.5,
  },
});
