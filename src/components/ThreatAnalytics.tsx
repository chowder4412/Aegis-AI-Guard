import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';
import { AlertTriangle, Shield, TrendingUp } from 'lucide-react-native';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import { subscribeToThreats } from '../services/securityDataService';
import type { Threat } from '../types';
import { fonts, palette, riskColors, shadows } from '../theme';

export const ThreatAnalytics = () => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) {
      setThreats([]);
      setLoading(false);
      return;
    }

    const unsubscribe = subscribeToThreats(
      user.uid,
      (items) => {
        setThreats(items);
        setLoading(false);
      },
      () => {
        setThreats([]);
        setLoading(false);
      },
      100,
    );

    return unsubscribe;
  }, [user]);

  const timelineData = useMemo(() => {
    const counts: Record<string, number> = {};
    threats.forEach((item) => {
      const key = new Date(item.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });
      counts[key] = (counts[key] ?? 0) + 1;
    });
    return Object.entries(counts).slice(-6).map(([label, count]) => ({ label, count }));
  }, [threats]);

  const categories = useMemo(() => {
    const counts: Record<string, number> = {};
    threats.forEach((item) => {
      counts[item.category] = (counts[item.category] ?? 0) + 1;
    });
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [threats]);

  const risks = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    threats.forEach((item) => {
      counts[item.risk] += 1;
    });
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [threats]);

  const maxTimeline = Math.max(...timelineData.map((item) => item.count), 1);
  const maxRisk = Math.max(...risks.map((item) => item.count), 1);

  if (loading) {
    return (
      <View style={styles.loadingCard}>
        <ActivityIndicator color={palette.secondary} size="large" />
        <Text style={styles.loadingText}>Aggregating global intelligence...</Text>
      </View>
    );
  }

  if (threats.length === 0) {
    return (
      <View style={styles.loadingCard}>
        <Shield color={palette.primaryMuted} size={32} />
        <Text style={styles.emptyTitle}>No analytics yet</Text>
        <Text style={styles.emptyBody}>Threat charts appear automatically after real scans create stored threat records.</Text>
      </View>
    );
  }

  return (
    <View style={[styles.grid, isDesktop && styles.gridDesktop]}>
      <View style={[styles.timelineCard, isMobile && styles.timelineCardMobile, isDesktop && styles.timelineCardDesktop]}>
        <View style={styles.titleRow}>
          <View style={styles.titleIconSecondary}>
            <TrendingUp color={palette.secondary} size={16} />
          </View>
          <Text style={styles.cardEyebrow}>Threat Propagation</Text>
        </View>

        <View style={styles.chartFrame}>
          {timelineData.map((item) => (
            <View key={item.label} style={styles.chartColumn}>
              <View style={styles.chartColumnTrack}>
                <View style={[styles.chartColumnFill, { height: `${(item.count / maxTimeline) * 100}%` }]} />
              </View>
              <Text style={styles.chartValue}>{item.count}</Text>
              <Text style={styles.chartLabel}>{item.label}</Text>
            </View>
          ))}
        </View>
      </View>

      <View style={[styles.sideColumn, isDesktop && styles.sideColumnDesktop]}>
        <View style={[styles.smallCard, isMobile && styles.smallCardMobile]}>
          <View style={styles.titleRow}>
            <View style={styles.titleIconPrimary}>
              <Shield color={palette.primary} size={16} />
            </View>
            <Text style={styles.cardEyebrow}>Vector Analysis</Text>
          </View>

          <View style={styles.legendList}>
            {categories.map((item) => (
              <View key={item.label} style={styles.legendRow}>
                <Text style={styles.legendLabel}>{item.label}</Text>
                <Text style={styles.legendValue}>{item.count}</Text>
              </View>
            ))}
          </View>
        </View>

        <View style={[styles.smallCard, isMobile && styles.smallCardMobile]}>
          <View style={styles.titleRow}>
            <View style={styles.titleIconAlert}>
              <AlertTriangle color={palette.error} size={16} />
            </View>
            <Text style={styles.cardEyebrow}>Severity Spread</Text>
          </View>

          <View style={styles.riskList}>
            {risks.map((item) => (
              <View key={item.label} style={styles.riskRow}>
                <View style={styles.riskRowHeader}>
                  <Text style={styles.riskLabel}>{item.label}</Text>
                  <Text style={styles.riskValue}>{item.count}</Text>
                </View>
                <View style={styles.riskTrack}>
                  <View
                    style={[
                      styles.riskFill,
                      {
                        width: `${(item.count / maxRisk) * 100}%`,
                        backgroundColor: riskColors[item.label as keyof typeof riskColors].fill,
                      },
                    ]}
                  />
                </View>
              </View>
            ))}
          </View>
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  loadingCard: {
    minHeight: 280,
    borderRadius: 32,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    ...shadows.card,
  },
  loadingText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  emptyTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  emptyBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 21,
    textAlign: 'center',
    maxWidth: 320,
  },
  grid: {
    gap: 18,
  },
  gridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  timelineCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 18,
    ...shadows.card,
  },
  timelineCardDesktop: {
    flex: 2,
  },
  timelineCardMobile: {
    borderRadius: 28,
    padding: 20,
  },
  sideColumn: {
    gap: 18,
  },
  sideColumnDesktop: {
    flex: 1,
  },
  smallCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 16,
    ...shadows.card,
  },
  smallCardMobile: {
    borderRadius: 28,
    padding: 20,
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  titleIconSecondary: {
    width: 34,
    height: 34,
    borderRadius: 14,
    backgroundColor: 'rgba(74,225,131,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  titleIconPrimary: {
    width: 34,
    height: 34,
    borderRadius: 14,
    backgroundColor: 'rgba(187,198,226,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  titleIconAlert: {
    width: 34,
    height: 34,
    borderRadius: 14,
    backgroundColor: 'rgba(255,92,82,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  cardEyebrow: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  chartFrame: {
    minHeight: 200,
    flexDirection: 'row',
    alignItems: 'flex-end',
    justifyContent: 'space-between',
    gap: 12,
  },
  chartColumn: {
    flex: 1,
    alignItems: 'center',
    gap: 8,
  },
  chartColumnTrack: {
    width: '100%',
    height: 140,
    justifyContent: 'flex-end',
    borderRadius: 20,
    backgroundColor: 'rgba(50,53,60,0.32)',
    overflow: 'hidden',
  },
  chartColumnFill: {
    width: '100%',
    backgroundColor: palette.warning,
    borderRadius: 20,
    minHeight: 16,
  },
  chartValue: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  chartLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 11,
  },
  legendList: {
    gap: 12,
  },
  legendRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderRadius: 16,
    backgroundColor: 'rgba(50,53,60,0.24)',
    paddingHorizontal: 14,
    paddingVertical: 14,
  },
  legendLabel: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  legendValue: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 16,
  },
  riskList: {
    gap: 14,
  },
  riskRow: {
    gap: 8,
  },
  riskRowHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  riskLabel: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  riskValue: {
    color: palette.primaryMuted,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
  },
  riskTrack: {
    height: 10,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.3)',
    overflow: 'hidden',
  },
  riskFill: {
    height: '100%',
    borderRadius: 999,
  },
});
