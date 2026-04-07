import { useEffect, useMemo, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { BookOpen, GraduationCap, Info, Lock, Mail, Play, Search, ShieldAlert } from 'lucide-react-native';
import type { AppTab } from '../components/BottomNavBar';
import { useAcademy } from '../context/AcademyContext';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { getAcademyLesson, getEducationSnapshot } from '../services/educationService';
import { subscribeToScanEvents, subscribeToThreats } from '../services/securityDataService';
import type { AcademyTrack, PracticeScenario, ScanEvent, Threat } from '../types';
import { categoryColors, fonts, palette, riskColors, shadows } from '../theme';

interface EducationProps {
  onNavigateTab?: (tab: AppTab) => void;
}

const getTrackAccent = (track: AcademyTrack) => {
  switch (track.audience) {
    case 'analyst':
      return { tint: 'rgba(79,123,255,0.16)', text: palette.info };
    case 'professional':
      return { tint: 'rgba(74,225,131,0.14)', text: palette.secondary };
    case 'beginner':
    default:
      return { tint: 'rgba(187,198,226,0.14)', text: palette.primary };
  }
};

export const Education = ({ onNavigateTab }: EducationProps) => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { linkedEmails } = useLinkedEmails();
  const { launchScenario, setActiveLessonId: setAcademyLessonId } = useAcademy();
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);

  useEffect(() => {
    if (!user) {
      setScanEvents([]);
      setThreats([]);
      return;
    }

    const unsubscribeScans = subscribeToScanEvents(user.uid, setScanEvents, () => setScanEvents([]), 50);
    const unsubscribeThreats = subscribeToThreats(user.uid, setThreats, () => setThreats([]), 30);

    return () => {
      unsubscribeScans();
      unsubscribeThreats();
    };
  }, [user]);

  const snapshot = useMemo(
    () =>
      getEducationSnapshot({
        scanEvents,
        threats,
        linkedEmails,
      }),
    [linkedEmails, scanEvents, threats],
  );

  const [activeLessonId, setActiveLessonId] = useState(snapshot.recommendedLessons[0]?.lessonId || snapshot.lessons[0]?.id || 'harvesting');

  useEffect(() => {
    const fallbackLessonId = snapshot.recommendedLessons[0]?.lessonId || snapshot.lessons[0]?.id;
    if (!fallbackLessonId) {
      return;
    }
    if (!getAcademyLesson(activeLessonId)) {
      setActiveLessonId(fallbackLessonId);
    }
  }, [activeLessonId, snapshot.lessons, snapshot.recommendedLessons]);

  const activeLesson = getAcademyLesson(activeLessonId) || snapshot.lessons[0];
  const activeRecommendation = snapshot.recommendedLessons.find((item) => item.lessonId === activeLesson?.id);
  const featuredBrief = snapshot.researchBriefs[0];
  const featuredScenario = snapshot.practiceScenarios[0];

  const openScenario = (scenario: PracticeScenario) => {
    setActiveLessonId(scenario.lessonId);
    setAcademyLessonId(scenario.lessonId);
    launchScenario(scenario);
    onNavigateTab?.('scanner');
  };

  const openLessonDrill = () => {
    const scenario =
      snapshot.practiceScenarios.find((item) => item.lessonId === activeLesson.id) || {
        id: `lesson-${activeLesson.id}`,
        title: `${activeLesson.title} drill`,
        summary: activeLesson.summary,
        inputType: 'email' as const,
        draftInput: activeLesson.practicePrompt,
        lessonId: activeLesson.id,
        sourceLabel: 'Aegis Research Academy',
        riskLevel: 'Medium' as const,
      };

    openScenario(scenario);
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={styles.badge}>
          <GraduationCap color={palette.secondary} size={14} />
          <Text style={styles.badgeText}>Aegis Research Academy</Text>
        </View>
        <Text style={[styles.title, isMobile && styles.titleMobile]}>
          Open research vision,
          {'\n'}
          <Text style={{ color: palette.secondary }}>personal defense execution.</Text>
        </Text>
        <Text style={[styles.body, isMobile && styles.bodyMobile]}>
          Aegis turns phishing research into adaptive training. Lessons are prioritized from live scans, mailbox telemetry, and threat signals so your team learns what matters now, not just what looked dangerous last quarter.
        </Text>
      </View>

      <View style={[styles.heroGrid, isDesktop && styles.heroGridDesktop]}>
        <View style={[styles.heroCard, isDesktop && styles.heroCardDesktop]}>
          <Text style={styles.heroEyebrow}>Research-to-Defense Engine</Text>
          <Text style={[styles.heroTitle, isMobile && styles.heroTitleMobile]}>
            Train from what Aegis is seeing in the wild and in your own protection graph.
          </Text>
          <Text style={styles.heroBody}>
            Sting9's open research vision becomes more powerful inside Aegis because every brief can map directly to a scanner drill, a mailbox defense decision, and the attack patterns already touching your workspace.
          </Text>

          <View style={styles.statRow}>
            <View style={styles.statCard}>
              <Text style={styles.statLabel}>Research Briefs</Text>
              <Text style={styles.statValue}>{snapshot.stats.researchBriefCount}</Text>
            </View>
            <View style={styles.statCard}>
              <Text style={styles.statLabel}>High-Risk Findings</Text>
              <Text style={styles.statValue}>{snapshot.stats.highRiskFindings}</Text>
            </View>
            <View style={styles.statCard}>
              <Text style={styles.statLabel}>Linked Mailboxes</Text>
              <Text style={styles.statValue}>{snapshot.stats.linkedMailboxCount}</Text>
            </View>
          </View>
        </View>

        <View style={styles.briefCard}>
          <Text style={styles.cardEyebrow}>Featured Research Brief</Text>
          <Text style={[styles.briefTitle, isMobile && styles.briefTitleMobile]}>{featuredBrief.title}</Text>
          <Text style={styles.briefBody}>{featuredBrief.summary}</Text>
          <View style={styles.briefMetaRow}>
            <View style={[styles.miniPill, featuredBrief.urgency === 'Critical' ? styles.criticalPill : styles.watchPill]}>
              <Text style={[styles.miniPillText, featuredBrief.urgency === 'Critical' ? styles.criticalPillText : styles.watchPillText]}>
                {featuredBrief.urgency}
              </Text>
            </View>
            <Text style={styles.metaText}>{featuredBrief.threatFamily}</Text>
          </View>
          <Text style={styles.researchSource}>{featuredBrief.source}</Text>
          <Text style={styles.briefAction}>{featuredBrief.action}</Text>
        </View>
      </View>

      <View style={styles.trackSection}>
        <Text style={styles.sectionEyebrow}>Academy Tracks</Text>
        <View style={[styles.trackGrid, isDesktop && styles.trackGridDesktop]}>
          {snapshot.tracks.map((track) => {
            const accent = getTrackAccent(track);
            return (
              <View key={track.id} style={styles.trackCard}>
                <View style={[styles.trackBadge, { backgroundColor: accent.tint }]}>
                  <Text style={[styles.trackBadgeText, { color: accent.text }]}>{track.audience}</Text>
                </View>
                <Text style={styles.trackTitle}>{track.title}</Text>
                <Text style={styles.trackBody}>{track.summary}</Text>
                <Text style={styles.trackFocus}>{track.focus}</Text>
              </View>
            );
          })}
        </View>
      </View>

      <View style={[styles.contentGrid, isDesktop && styles.contentGridDesktop]}>
        <View style={[styles.column, isDesktop && styles.columnWide]}>
          <View style={styles.recommendationCard}>
            <Text style={styles.cardEyebrow}>Your Recommended Lessons</Text>
            <View style={styles.recommendationList}>
              {snapshot.recommendedLessons.map((recommendation) => {
                const lesson = getAcademyLesson(recommendation.lessonId);
                if (!lesson) {
                  return null;
                }
                const categoryTint = categoryColors[lesson.category];
                const isActive = lesson.id === activeLesson?.id;
                return (
                  <Pressable
                    key={recommendation.lessonId}
                    onPress={() => setActiveLessonId(recommendation.lessonId)}
                    style={({ pressed }) => [
                      styles.recommendationItem,
                      isActive && styles.recommendationItemActive,
                      pressed && styles.pressed,
                    ]}
                  >
                    <View style={styles.recommendationTop}>
                      <View style={[styles.miniPill, { backgroundColor: categoryTint.tint }]}>
                        <Text style={[styles.miniPillText, { color: categoryTint.text }]}>{recommendation.priority}</Text>
                      </View>
                      <Text style={styles.recommendationSignal}>{recommendation.signal}</Text>
                    </View>
                    <Text style={styles.recommendationTitle}>{lesson.title}</Text>
                    <Text style={styles.recommendationBody}>{recommendation.reason}</Text>
                  </Pressable>
                );
              })}
            </View>
          </View>

          <View style={styles.workspaceCard}>
            <View style={styles.workspaceHeader}>
              <Text style={styles.cardEyebrow}>Lesson Workspace</Text>
              <View style={[styles.miniPill, { backgroundColor: categoryColors[activeLesson.category].tint }]}>
                <Text style={[styles.miniPillText, { color: categoryColors[activeLesson.category].text }]}>{activeLesson.difficulty}</Text>
              </View>
            </View>
            <Text style={[styles.workspaceTitle, isMobile && styles.workspaceTitleMobile]}>{activeLesson.title}</Text>
            <Text style={styles.workspaceSummary}>{activeLesson.summary}</Text>
            <Text style={styles.workspaceBody}>{activeLesson.body}</Text>

            {activeRecommendation ? (
              <View style={styles.signalBox}>
                <ShieldAlert color={palette.secondary} size={18} />
                <View style={{ flex: 1 }}>
                  <Text style={styles.signalTitle}>Why Aegis is recommending this now</Text>
                  <Text style={styles.signalBody}>{activeRecommendation.reason}</Text>
                </View>
              </View>
            ) : null}

            <View style={styles.workspaceFooter}>
              <View style={styles.lessonPill}>
                <BookOpen color={palette.secondary} size={14} />
                <Text style={styles.lessonPillText}>
                  {activeLesson.audience} track · {activeLesson.estimatedMinutes} min
                </Text>
              </View>
              <Pressable onPress={openLessonDrill} style={({ pressed }) => [styles.lessonRouteButton, pressed && styles.pressed]}>
                <Search color="#263046" size={16} />
                <Text style={styles.lessonRouteButtonText}>Practice In Scanner</Text>
              </Pressable>
            </View>
            <Text style={styles.practicePrompt}>{activeLesson.practicePrompt}</Text>
            <Text style={styles.researchSource}>{activeLesson.researchSource}</Text>
          </View>
        </View>

        <View style={styles.column}>
          <View style={styles.practiceCard}>
            <Text style={styles.cardEyebrow}>Practice From Real Signals</Text>
            <Text style={styles.practiceLead}>
              Aegis uses live scan history and recent threats to turn education into drills, not passive reading.
            </Text>
            <View style={styles.practiceList}>
              {snapshot.practiceScenarios.map((scenario, index) => (
                <View key={scenario.id} style={styles.practiceItem}>
                  <View style={styles.practiceIndex}>
                    <Text style={styles.practiceIndexText}>{index + 1}</Text>
                  </View>
                  <View style={{ flex: 1, gap: 6 }}>
                    <View style={styles.practiceTop}>
                      <Text style={styles.practiceTitle}>{scenario.title}</Text>
                      <View style={[styles.miniPill, { backgroundColor: riskColors[scenario.riskLevel].tint }]}>
                        <Text style={[styles.miniPillText, { color: riskColors[scenario.riskLevel].text }]}>{scenario.riskLevel}</Text>
                      </View>
                    </View>
                    <Text style={styles.practiceBody}>{scenario.summary}</Text>
                    <Text style={styles.practiceSource}>{scenario.sourceLabel}</Text>
                    <Text style={styles.practiceDraft} numberOfLines={2}>
                      {scenario.draftInput}
                    </Text>
                    <View style={styles.practiceActions}>
                      <Pressable onPress={() => openScenario(scenario)} style={({ pressed }) => [styles.secondaryCta, pressed && styles.pressed]}>
                        <Play color="#263046" size={14} />
                        <Text style={styles.secondaryCtaText}>Open Drill</Text>
                      </Pressable>
                      <Pressable onPress={() => setActiveLessonId(scenario.lessonId)} style={({ pressed }) => [styles.iconButton, pressed && styles.pressed]}>
                        <Info color={palette.onSurface} size={16} />
                      </Pressable>
                    </View>
                  </View>
                </View>
              ))}
            </View>
          </View>

          <View style={styles.visionCard}>
            <View style={styles.visionTop}>
              <Mail color={palette.secondary} size={18} />
              <Text style={styles.cardEyebrow}>Vision Beyond Static Courses</Text>
            </View>
            <Text style={styles.visionTitle}>Aegis can surpass Sting9 by becoming the coach, not just the library.</Text>
            <Text style={styles.visionBody}>
              Open research is only the beginning. The real moat is converting intelligence into adaptive learning loops: what users scanned, what mailboxes saw, what nearly worked, and what Aegis should teach next.
            </Text>
            <View style={styles.visionBullets}>
              <Text style={styles.visionBullet}>Personalized lessons from real scan history</Text>
              <Text style={styles.visionBullet}>Mailbox-aware coaching from live protection signals</Text>
              <Text style={styles.visionBullet}>Research briefs that turn directly into drills</Text>
            </View>
          </View>

          <View style={styles.footerCard}>
            <Text style={styles.footerEyebrow}>Neural Learning Sync</Text>
            <Text style={[styles.footerTitle, isMobile && styles.footerTitleMobile]}>
              {snapshot.stats.highRiskFindings > 0 ? `${snapshot.stats.highRiskFindings} high-risk findings` : 'No critical findings yet'}
            </Text>
            <Text style={styles.footerBody}>
              {featuredScenario
                ? 'Education is now anchored to live signals. Scanner drills and the learning queue turn practice into future model and lesson improvements.'
                : 'Education is ready to become your research-to-defense layer.'}
            </Text>
            <View style={styles.footerActionRow}>
              <Pressable
                onPress={() => (featuredScenario ? openScenario(featuredScenario) : onNavigateTab?.('scanner'))}
                style={({ pressed }) => [styles.lessonRouteButton, pressed && styles.pressed]}
              >
                <Search color="#263046" size={16} />
                <Text style={styles.lessonRouteButtonText}>Run Practice Scan</Text>
              </Pressable>
              <View style={styles.lockRow}>
                <Text style={styles.lockedText}>Adaptive coaching live</Text>
                <Lock color={palette.primaryMuted} size={16} />
              </View>
            </View>
          </View>
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    gap: 22,
    width: '100%',
    maxWidth: 1320,
    alignSelf: 'center',
  },
  header: {
    gap: 16,
  },
  badge: {
    alignSelf: 'flex-start',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 14,
    backgroundColor: 'rgba(6,187,99,0.12)',
  },
  badgeText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  title: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 54,
    lineHeight: 58,
  },
  titleMobile: {
    fontSize: 34,
    lineHeight: 40,
  },
  body: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 18,
    lineHeight: 27,
    maxWidth: 720,
  },
  bodyMobile: {
    fontSize: 15,
    lineHeight: 23,
    maxWidth: undefined,
  },
  heroGrid: {
    gap: 18,
  },
  heroGridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  heroCard: {
    borderRadius: 36,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 26,
    gap: 18,
    ...shadows.card,
  },
  heroCardDesktop: {
    flex: 1.45,
  },
  heroEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  heroTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 36,
    lineHeight: 40,
  },
  heroTitleMobile: {
    fontSize: 28,
    lineHeight: 32,
  },
  heroBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 15,
    lineHeight: 23,
  },
  statRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 12,
  },
  statCard: {
    minWidth: 120,
    flex: 1,
    borderRadius: 22,
    backgroundColor: 'rgba(50,53,60,0.26)',
    padding: 16,
    gap: 6,
  },
  statLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  statValue: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 26,
  },
  briefCard: {
    flex: 1,
    borderRadius: 36,
    backgroundColor: 'rgba(74,225,131,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.18)',
    padding: 24,
    gap: 14,
    ...shadows.card,
  },
  cardEyebrow: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  briefTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 28,
    lineHeight: 32,
  },
  briefTitleMobile: {
    fontSize: 24,
    lineHeight: 28,
  },
  briefBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  briefMetaRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    flexWrap: 'wrap',
  },
  metaText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  researchSource: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  briefAction: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
    lineHeight: 20,
  },
  trackSection: {
    gap: 14,
  },
  sectionEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  trackGrid: {
    gap: 14,
  },
  trackGridDesktop: {
    flexDirection: 'row',
  },
  trackCard: {
    flex: 1,
    borderRadius: 28,
    backgroundColor: 'rgba(39,45,52,0.78)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 10,
    ...shadows.card,
  },
  trackBadge: {
    alignSelf: 'flex-start',
    borderRadius: 999,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  trackBadgeText: {
    fontFamily: fonts.headlineBold,
    fontSize: 9,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  trackTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 22,
  },
  trackBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 21,
  },
  trackFocus: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
    lineHeight: 18,
  },
  contentGrid: {
    gap: 18,
  },
  contentGridDesktop: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  column: {
    gap: 18,
    flex: 1,
  },
  columnWide: {
    flex: 1.2,
  },
  recommendationCard: {
    borderRadius: 32,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 22,
    gap: 16,
    ...shadows.card,
  },
  recommendationList: {
    gap: 12,
  },
  recommendationItem: {
    borderRadius: 22,
    backgroundColor: 'rgba(50,53,60,0.22)',
    padding: 16,
    gap: 8,
  },
  recommendationItemActive: {
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.3)',
    backgroundColor: 'rgba(74,225,131,0.06)',
  },
  recommendationTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 10,
  },
  recommendationSignal: {
    flex: 1,
    textAlign: 'right',
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  recommendationTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  recommendationBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 20,
  },
  miniPill: {
    alignSelf: 'flex-start',
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  miniPillText: {
    fontFamily: fonts.headlineBold,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  criticalPill: {
    backgroundColor: 'rgba(255,92,82,0.16)',
  },
  watchPill: {
    backgroundColor: 'rgba(187,198,226,0.14)',
  },
  criticalPillText: {
    color: palette.error,
  },
  watchPillText: {
    color: palette.primary,
  },
  workspaceCard: {
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.16)',
    backgroundColor: 'rgba(18,23,31,0.82)',
    padding: 24,
    gap: 14,
    ...shadows.card,
  },
  workspaceHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  workspaceTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 30,
    lineHeight: 34,
  },
  workspaceTitleMobile: {
    fontSize: 24,
    lineHeight: 28,
  },
  workspaceSummary: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
    lineHeight: 22,
  },
  workspaceBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  signalBox: {
    flexDirection: 'row',
    gap: 12,
    borderRadius: 22,
    backgroundColor: 'rgba(74,225,131,0.08)',
    padding: 16,
  },
  signalTitle: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  signalBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 20,
    marginTop: 4,
  },
  workspaceFooter: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  lessonPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    borderRadius: 999,
    backgroundColor: 'rgba(74,225,131,0.08)',
    paddingHorizontal: 14,
    paddingVertical: 10,
  },
  lessonPillText: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  lessonRouteButton: {
    borderRadius: 18,
    backgroundColor: palette.primary,
    paddingHorizontal: 18,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  lessonRouteButtonText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  practicePrompt: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
    lineHeight: 20,
  },
  practiceCard: {
    borderRadius: 32,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 22,
    gap: 14,
    ...shadows.card,
  },
  practiceLead: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  practiceList: {
    gap: 14,
  },
  practiceItem: {
    flexDirection: 'row',
    gap: 12,
    borderRadius: 22,
    backgroundColor: 'rgba(50,53,60,0.24)',
    padding: 16,
  },
  practiceIndex: {
    width: 30,
    height: 30,
    borderRadius: 15,
    backgroundColor: 'rgba(74,225,131,0.14)',
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 2,
  },
  practiceIndexText: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 12,
  },
  practiceTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  practiceTitle: {
    flex: 1,
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
  },
  practiceBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 20,
  },
  practiceSource: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  practiceDraft: {
    color: palette.primary,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
    lineHeight: 18,
  },
  practiceActions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginTop: 4,
  },
  secondaryCta: {
    borderRadius: 18,
    backgroundColor: palette.primary,
    paddingHorizontal: 16,
    paddingVertical: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  secondaryCtaText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  iconButton: {
    width: 42,
    height: 42,
    borderRadius: 14,
    backgroundColor: palette.surfaceHighest,
    alignItems: 'center',
    justifyContent: 'center',
  },
  visionCard: {
    borderRadius: 32,
    backgroundColor: 'rgba(79,123,255,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(79,123,255,0.18)',
    padding: 22,
    gap: 12,
    ...shadows.card,
  },
  visionTop: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  visionTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 24,
    lineHeight: 28,
  },
  visionBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  visionBullets: {
    gap: 8,
  },
  visionBullet: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
    lineHeight: 19,
  },
  footerCard: {
    borderRadius: 32,
    padding: 24,
    gap: 12,
    backgroundColor: 'rgba(74,225,131,0.06)',
    ...shadows.card,
  },
  footerEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  footerTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 34,
    lineHeight: 38,
  },
  footerTitleMobile: {
    fontSize: 26,
    lineHeight: 30,
  },
  footerBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  footerActionRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    marginTop: 4,
  },
  lockRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 8,
  },
  lockedText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  pressed: {
    opacity: 0.92,
  },
});
