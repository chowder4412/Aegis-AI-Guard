import { useEffect, useMemo, useState } from 'react';
import { Linking, Modal, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { Bot, BrainCircuit, CheckCircle2, Filter, Globe, Link2Off, Mail, ShieldAlert } from 'lucide-react-native';
import { markThreatReviewed, subscribeToThreats } from '../services/securityDataService';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import type { Threat } from '../types';
import { categoryColors, fonts, formatRelativeTime, palette, riskColors, shadows } from '../theme';

type FilterType = 'All' | 'Critical' | 'High' | 'Medium' | 'Low';

interface ThreatFeedProps {
  isLinked?: boolean;
}

export const ThreatFeed = ({ isLinked = false }: ThreatFeedProps) => {
  const { isTablet } = useResponsive();
  const isMobile = !isTablet;
  const [threats, setThreats] = useState<Threat[]>([]);
  const [activeFilter, setActiveFilter] = useState<FilterType>('All');
  const [confirmReviewId, setConfirmReviewId] = useState<string | null>(null);
  const { user } = useAuth();

  useEffect(() => {
    if (!user) {
      setThreats([]);
      return;
    }

    const unsubscribe = subscribeToThreats(
      user.uid,
      (items) => {
        setThreats(items);
      },
      () => {
        setThreats([]);
      },
    );

    return unsubscribe;
  }, [user]);

  const filteredThreats = useMemo(() => {
    const list = activeFilter === 'All' ? threats : threats.filter((item) => item.risk === activeFilter);
    const priority = { Critical: 0, High: 1, Medium: 2, Low: 3 };
    return [...list].sort((left, right) => priority[left.risk] - priority[right.risk]);
  }, [activeFilter, threats]);

  const visibleThreats = filteredThreats.slice(0, 6);

  const handleReview = async (id: string) => {
    setThreats((current) => current.map((item) => (item.id === id ? { ...item, status: 'reviewed' } : item)));
    setConfirmReviewId(null);

    if (!user) {
      return;
    }
    await markThreatReviewed(user.uid, id);
  };

  return (
    <View style={styles.section}>
      <View style={[styles.topRow, isMobile && styles.topRowMobile]}>
        <View style={styles.statusRow}>
          <View style={[styles.statusPulse, { backgroundColor: isLinked ? palette.success : palette.errorStrong }]} />
          <Text style={styles.title}>{isLinked ? 'Real-time Bot Protection Active' : 'Live Threat Feed'}</Text>
        </View>

        {isLinked ? (
          <View style={styles.syncedBadge}>
            <Bot color={palette.success} size={12} />
            {!isMobile ? <Text style={styles.syncedBadgeText}>Synchronized with inbox</Text> : null}
          </View>
        ) : null}
      </View>

      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={styles.filterRow}>
        <View style={styles.filterLead}>
          <Filter color={palette.primaryMuted} size={12} />
          <Text style={styles.filterLeadText}>Filter</Text>
        </View>
        {(['All', 'Critical', 'High', 'Medium', 'Low'] as FilterType[]).map((filter) => {
          const active = activeFilter === filter;
          return (
            <Pressable
              key={filter}
              onPress={() => setActiveFilter(filter)}
              style={[styles.filterChip, active && styles.filterChipActive]}
            >
              <Text style={[styles.filterChipText, active && styles.filterChipTextActive]}>{filter}</Text>
            </Pressable>
          );
        })}
      </ScrollView>

      <View style={[styles.feedCard, isMobile && styles.feedCardMobile]}>
        {visibleThreats.length === 0 ? (
          <View style={styles.emptyState}>
            <ShieldAlert color={palette.primaryMuted} size={40} />
            <Text style={styles.emptyText}>{isLinked ? 'No stored threats for this filter yet' : 'Link a mailbox or run a scan to populate live threats'}</Text>
          </View>
        ) : (
          visibleThreats.map((threat) => {
            const severityScore = Math.round((threat.aiAnalysis.impactScore * 10 + threat.aiAnalysis.confidence) / 2);
            const riskStyle = riskColors[threat.risk];
            return (
              <View
                key={threat.id}
                style={[
                  styles.threatCard,
                  isMobile && styles.threatCardMobile,
                  {
                    backgroundColor: riskStyle.tint,
                    borderColor: 'rgba(68,71,76,0.28)',
                    opacity: threat.status === 'reviewed' ? 0.45 : 1,
                  },
                ]}
              >
                <View style={styles.threatTop}>
                  <View style={styles.threatLeft}>
                    <View style={styles.threatIconWrap}>
                      {threat.type.includes('Harvesting') ? (
                        <Link2Off color={palette.onSurface} size={18} />
                      ) : threat.type.includes('Email') || threat.type.includes('Phishing') ? (
                        <Mail color={palette.onSurface} size={18} />
                      ) : (
                        <ShieldAlert color={palette.onSurface} size={18} />
                      )}
                    </View>
                    <View style={{ flex: 1 }}>
                      <View style={styles.threatMetaRow}>
                        <Text style={styles.threatSource}>{threat.source}</Text>
                        <Text style={styles.threatTime}>{formatRelativeTime(threat.timestamp)}</Text>
                      </View>
                      <View style={styles.threatLabels}>
                        <View
                          style={[
                            styles.categoryChip,
                            { backgroundColor: categoryColors[threat.category].tint, borderColor: 'transparent' },
                          ]}
                        >
                          <Text style={[styles.categoryChipText, { color: categoryColors[threat.category].text }]}>
                            {threat.category}
                          </Text>
                        </View>
                        <View style={styles.confidenceChip}>
                          <BrainCircuit color={palette.secondary} size={10} />
                          <Text style={styles.confidenceChipText}>{threat.aiAnalysis.confidence}% confidence</Text>
                        </View>
                      </View>
                      <Text style={styles.threatType}>{threat.type}</Text>
                    </View>
                  </View>

                  {threat.status !== 'reviewed' ? (
                    <Pressable onPress={() => setConfirmReviewId(threat.id)} style={styles.reviewButton}>
                      <CheckCircle2 color={palette.secondary} size={16} />
                    </Pressable>
                  ) : null}
                </View>

                <View style={styles.summaryBox}>
                  <Text style={styles.summaryLabel}>AI Summary</Text>
                  <Text style={styles.summaryText}>{threat.aiAnalysis.summary}</Text>
                  <Text style={styles.summarySubtext}>{threat.aiAnalysis.detailedSummary}</Text>
                </View>

                <View style={[styles.metricsGrid, isMobile && styles.metricsGridMobile]}>
                  <View style={[styles.metricTile, isMobile && styles.metricTileMobile]}>
                    <Text style={styles.metricTileLabel}>Recommendation</Text>
                    <Text style={styles.metricTileBody}>{threat.aiAnalysis.recommendation}</Text>
                  </View>
                  <View style={[styles.metricTile, isMobile && styles.metricTileMobile]}>
                    <Text style={styles.metricTileLabel}>Detection Method</Text>
                    <Text style={styles.metricTileBody}>{threat.aiAnalysis.detectionMethod}</Text>
                  </View>
                </View>

                <View style={[styles.metricsGrid, isMobile && styles.metricsGridMobile]}>
                  <View style={[styles.metricTile, isMobile && styles.metricTileMobile]}>
                    <Text style={styles.metricTileLabel}>Affected Assets</Text>
                    <Text style={styles.metricTileBody}>{threat.aiAnalysis.affectedAssets.join(', ')}</Text>
                  </View>
                  <Pressable
                    onPress={() => void Linking.openURL(`https://attack.mitre.org/techniques/${threat.aiAnalysis.mitreTechnique.replace('.', '/')}/`)}
                    style={[styles.metricTile, isMobile && styles.metricTileMobile]}
                  >
                    <View style={styles.metricLinkRow}>
                      <Text style={styles.metricTileLabel}>MITRE ATT&CK</Text>
                      <Globe color={palette.secondary} size={12} />
                    </View>
                    <Text style={styles.metricTileBody}>
                      {threat.aiAnalysis.mitreTechnique} - {threat.aiAnalysis.mitreTactic}
                    </Text>
                  </Pressable>
                </View>

                <View style={[styles.bottomRow, isMobile && styles.bottomRowMobile]}>
                  <View style={[styles.riskPill, { backgroundColor: riskStyle.tint }]}>
                    <Text style={[styles.riskPillText, { color: riskStyle.text }]}>{threat.risk}</Text>
                  </View>
                  <View style={styles.severityWrap}>
                    <Text style={styles.severityLabel}>AI Severity {severityScore}</Text>
                    <View style={styles.severityTrack}>
                      <View style={[styles.severityFill, { width: `${severityScore}%`, backgroundColor: riskStyle.fill }]} />
                    </View>
                  </View>
                </View>
              </View>
            );
          })
        )}
      </View>

      <Modal animationType="fade" onRequestClose={() => setConfirmReviewId(null)} transparent visible={!!confirmReviewId}>
        <View style={styles.modalBackdrop}>
          <View style={styles.modalCard}>
            <View style={styles.modalIcon}>
              <CheckCircle2 color={palette.secondary} size={32} />
            </View>
            <Text style={styles.modalTitle}>Mark as Reviewed?</Text>
            <Text style={styles.modalBody}>This threat will be archived and removed from your active feed.</Text>
            <View style={styles.modalButtons}>
              <Pressable onPress={() => setConfirmReviewId(null)} style={styles.modalSecondary}>
                <Text style={styles.modalSecondaryText}>Cancel</Text>
              </Pressable>
              <Pressable onPress={() => (confirmReviewId ? void handleReview(confirmReviewId) : undefined)} style={styles.modalPrimary}>
                <Text style={styles.modalPrimaryText}>Confirm</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
};

const styles = StyleSheet.create({
  section: {
    gap: 14,
  },
  topRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  topRowMobile: {
    alignItems: 'flex-start',
    flexWrap: 'wrap',
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    flex: 1,
  },
  statusPulse: {
    width: 10,
    height: 10,
    borderRadius: 5,
  },
  title: {
    color: palette.onSurface,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  syncedBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 10,
    paddingVertical: 6,
    borderRadius: 999,
    backgroundColor: 'rgba(39,198,122,0.12)',
  },
  syncedBadgeText: {
    color: palette.success,
    fontFamily: fonts.headlineBold,
    fontSize: 8,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  filterRow: {
    gap: 10,
    alignItems: 'center',
  },
  filterLead: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginRight: 4,
  },
  filterLeadText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  filterChip: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: 'rgba(50,53,60,0.3)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
  },
  filterChipActive: {
    backgroundColor: palette.secondary,
    borderColor: palette.secondary,
  },
  filterChipText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  filterChipTextActive: {
    color: palette.onSecondary,
  },
  feedCard: {
    borderRadius: 32,
    backgroundColor: 'rgba(11,14,20,0.58)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 16,
    gap: 14,
    ...shadows.card,
  },
  feedCardMobile: {
    borderRadius: 28,
    padding: 14,
  },
  threatCard: {
    borderRadius: 24,
    borderWidth: 1,
    padding: 16,
    gap: 14,
  },
  threatCardMobile: {
    borderRadius: 20,
    padding: 14,
    gap: 12,
  },
  threatTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  threatLeft: {
    flex: 1,
    flexDirection: 'row',
    gap: 12,
  },
  threatIconWrap: {
    width: 40,
    height: 40,
    borderRadius: 16,
    backgroundColor: 'rgba(50,53,60,0.34)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  threatMetaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    flexWrap: 'wrap',
  },
  threatSource: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 14,
    flexShrink: 1,
  },
  threatTime: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 11,
  },
  threatLabels: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    flexWrap: 'wrap',
    marginTop: 6,
  },
  categoryChip: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 5,
  },
  categoryChipText: {
    fontFamily: fonts.headlineBold,
    fontSize: 9,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  confidenceChip: {
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 5,
    backgroundColor: 'rgba(74,225,131,0.08)',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  confidenceChipText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  threatType: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    marginTop: 6,
  },
  reviewButton: {
    padding: 6,
  },
  summaryBox: {
    borderRadius: 18,
    padding: 14,
    backgroundColor: 'rgba(50,53,60,0.24)',
    gap: 6,
  },
  summaryLabel: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  summaryText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
    lineHeight: 20,
  },
  summarySubtext: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  metricsGrid: {
    flexDirection: 'row',
    gap: 10,
  },
  metricsGridMobile: {
    flexDirection: 'column',
  },
  metricTile: {
    flex: 1,
    borderRadius: 18,
    padding: 14,
    backgroundColor: 'rgba(50,53,60,0.24)',
    gap: 6,
  },
  metricTileMobile: {
    borderRadius: 16,
    padding: 12,
  },
  metricTileLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.3,
    textTransform: 'uppercase',
  },
  metricTileBody: {
    color: palette.onSurface,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
    lineHeight: 18,
  },
  metricLinkRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  bottomRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  bottomRowMobile: {
    flexDirection: 'column',
    alignItems: 'stretch',
  },
  riskPill: {
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  riskPillText: {
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  severityWrap: {
    flex: 1,
    gap: 6,
  },
  severityLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  severityTrack: {
    height: 8,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.4)',
    overflow: 'hidden',
  },
  severityFill: {
    height: '100%',
    borderRadius: 999,
  },
  emptyState: {
    minHeight: 180,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  emptyText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  modalBackdrop: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.58)',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
  },
  modalCard: {
    width: '100%',
    maxWidth: 360,
    borderRadius: 28,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.34)',
    padding: 24,
    alignItems: 'center',
    gap: 12,
  },
  modalIcon: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: 'rgba(74,225,131,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  modalTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 24,
    textAlign: 'center',
  },
  modalBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
    textAlign: 'center',
  },
  modalButtons: {
    width: '100%',
    flexDirection: 'row',
    gap: 10,
    marginTop: 8,
  },
  modalSecondary: {
    flex: 1,
    borderRadius: 18,
    paddingVertical: 14,
    alignItems: 'center',
    backgroundColor: palette.surfaceHighest,
  },
  modalSecondaryText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  modalPrimary: {
    flex: 1,
    borderRadius: 18,
    paddingVertical: 14,
    alignItems: 'center',
    backgroundColor: palette.secondary,
  },
  modalPrimaryText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
});
