import { useState } from 'react';
import { Image, Pressable, StyleSheet, Text, View } from 'react-native';
import { BookOpen, GraduationCap, Info, Lock, Play, Search } from 'lucide-react-native';
import type { AppTab } from '../components/BottomNavBar';
import { useResponsive } from '../hooks/useResponsive';
import { fonts, palette, shadows } from '../theme';

interface EducationProps {
  onNavigateTab?: (tab: AppTab) => void;
}

const lessons = {
  homoglyphs: {
    id: 'homoglyphs',
    title: 'Spotting Homoglyphs',
    summary: 'Identify lookalike domains and deceptive URL characters before they land a credential theft.',
    body: 'This lesson teaches how attackers swap characters like O and 0 or use unicode lookalikes to impersonate real brands. Use it when reviewing login prompts, shortened links, and account-verification emails.',
    progress: '65%',
  },
  masking: {
    id: 'masking',
    title: 'Link Masking',
    summary: 'Reveal hidden redirect chains and shortened URLs before trusting a destination.',
    body: 'This lesson focuses on link previews, redirect chains, shortened URLs, and visual trust cues that hide malicious destinations. It pairs well with the live scanner because you can practice on suspicious links immediately after reading the lesson.',
    progress: '12%',
  },
  harvesting: {
    id: 'harvesting',
    title: 'Credential Harvesting',
    summary: 'Understand how fake sign-in portals capture passwords in seconds.',
    body: 'This module covers cloned login pages, suspicious form behavior, domain mismatch patterns, and why a page asking for credentials after a redirect deserves immediate scrutiny.',
    progress: 'Advanced',
  },
} as const;

export const Education = ({ onNavigateTab }: EducationProps) => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const [activeLessonId, setActiveLessonId] = useState<keyof typeof lessons>('homoglyphs');
  const activeLesson = lessons[activeLessonId];
  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <View style={styles.badge}>
          <GraduationCap color={palette.secondary} size={14} />
          <Text style={styles.badgeText}>Academy Protocol</Text>
        </View>
        <Text style={[styles.title, isMobile && styles.titleMobile]}>Phishing Academy</Text>
        <Text style={[styles.body, isMobile && styles.bodyMobile]}>
          Elevate your digital intuition with curated modules that mirror the original security academy experience in native form.
        </Text>
      </View>

      <View style={styles.grid}>
        <View style={[styles.topGrid, isDesktop && styles.topGridDesktop]}>
          <View style={[styles.featuredCard, isMobile && styles.featuredCardMobile, isDesktop && styles.featuredCardDesktop]}>
          <Image
            source={{ uri: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=800&auto=format&fit=crop' }}
            style={styles.featuredImage}
          />
          <View style={styles.featuredOverlay} />
          <View style={[styles.featuredContent, isMobile && styles.featuredContentMobile]}>
            <View style={[styles.featuredTop, isMobile && styles.featuredTopMobile]}>
              <View style={{ flex: 1 }}>
                <Text style={[styles.featuredTitle, isMobile && styles.featuredTitleMobile]}>Spotting Homoglyphs</Text>
                <Text style={[styles.featuredBody, isMobile && styles.featuredBodyMobile]}>
                  Master the art of identifying visual deception in URL characters and lookalike domains.
                </Text>
              </View>
              <View style={[styles.featuredIcon, isMobile && styles.featuredIconMobile]}>
                <Search color={palette.secondary} size={28} />
              </View>
            </View>

            <View style={styles.progressWrap}>
              <View style={styles.progressHeader}>
                <Text style={styles.progressLabel}>Progress</Text>
                <Text style={styles.progressLabel}>65%</Text>
              </View>
              <View style={styles.progressTrack}>
                <View style={styles.progressFill} />
              </View>
            </View>

            <Pressable onPress={() => setActiveLessonId('homoglyphs')} style={({ pressed }) => [styles.ctaButton, pressed && styles.pressed]}>
              <Play color="#263046" size={18} />
              <Text style={styles.ctaText}>Open Lesson</Text>
            </Pressable>
          </View>
          </View>

          <View style={[styles.sideModuleColumn, isDesktop && styles.sideModuleColumnDesktop]}>
            <View style={styles.smallCard}>
          <View style={styles.smallIconError}>
            <BookOpen color={palette.error} size={22} />
          </View>
          <Text style={[styles.smallTitle, isMobile && styles.smallTitleMobile]}>Urgency Tactics</Text>
          <Text style={[styles.smallBody, isMobile && styles.smallBodyMobile]}>
            Deconstruct the psychological triggers used to bypass critical thinking during attacks.
          </Text>
          <View style={styles.lockRow}>
            <Text style={styles.lockedText}>Locked</Text>
            <Lock color={palette.primaryMuted} size={16} />
          </View>
          <View style={styles.disabledButton}>
            <Text style={styles.disabledButtonText}>Resume Module</Text>
          </View>
            </View>

            <View style={styles.smallCard}>
          <View style={styles.smallIconPrimary}>
            <BookOpen color={palette.primary} size={22} />
          </View>
          <Text style={[styles.smallTitle, isMobile && styles.smallTitleMobile]}>Link Masking</Text>
          <Text style={[styles.smallBody, isMobile && styles.smallBodyMobile]}>Reveal hidden destinations and shortening service vulnerabilities.</Text>
          <View style={styles.progressTrack}>
            <View style={[styles.progressFill, { width: '12%', backgroundColor: palette.primary }]} />
          </View>
          <Pressable onPress={() => setActiveLessonId('masking')} style={({ pressed }) => [styles.secondaryCta, pressed && styles.pressed]}>
            <Text style={styles.secondaryCtaText}>Open Lesson</Text>
          </Pressable>
            </View>
          </View>
        </View>

        <View style={[styles.mediumCard, isMobile && styles.mediumCardMobile, isDesktop && styles.mediumCardDesktop]}>
          <Image
            source={{ uri: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=500&auto=format&fit=crop' }}
            style={styles.mediumImage}
          />
          <View style={styles.mediumContent}>
            <View style={styles.advancedBadge}>
              <Text style={styles.advancedBadgeText}>Advanced</Text>
            </View>
            <Text style={[styles.mediumTitle, isMobile && styles.mediumTitleMobile]}>Credential Harvesting</Text>
            <Text style={[styles.mediumBody, isMobile && styles.mediumBodyMobile]}>
              Deep dive into fake login portals and how data is exfiltrated in milliseconds.
            </Text>
            <View style={styles.mediumActions}>
              <Pressable onPress={() => setActiveLessonId('harvesting')} style={({ pressed }) => [styles.iconButton, pressed && styles.pressed]}>
                <Info color={palette.onSurface} size={18} />
              </Pressable>
              <Pressable onPress={() => setActiveLessonId('harvesting')} style={({ pressed }) => [styles.secondaryCta, { flex: 1 }, pressed && styles.pressed]}>
                <Text style={styles.secondaryCtaText}>Open Lesson</Text>
              </Pressable>
            </View>
          </View>
        </View>
      </View>

      <View style={[styles.lessonWorkspace, isDesktop && styles.lessonWorkspaceDesktop]}>
        <View style={styles.lessonWorkspaceHeader}>
          <Text style={styles.lessonWorkspaceEyebrow}>Lesson Workspace</Text>
          <Text style={[styles.lessonWorkspaceTitle, isMobile && styles.lessonWorkspaceTitleMobile]}>{activeLesson.title}</Text>
        </View>
        <Text style={styles.lessonWorkspaceSummary}>{activeLesson.summary}</Text>
        <Text style={styles.lessonWorkspaceBody}>{activeLesson.body}</Text>
        <View style={styles.lessonWorkspaceFooter}>
          <View style={styles.lessonPill}>
            <BookOpen color={palette.secondary} size={14} />
            <Text style={styles.lessonPillText}>Lesson Progress {activeLesson.progress}</Text>
          </View>
          <Pressable onPress={() => onNavigateTab?.('scanner')} style={({ pressed }) => [styles.lessonRouteButton, pressed && styles.pressed]}>
            <Search color="#263046" size={16} />
            <Text style={styles.lessonRouteButtonText}>Practice In Scanner</Text>
          </Pressable>
        </View>
      </View>

      <View style={styles.footer}>
        <Text style={styles.footerEyebrow}>Neural Learning Sync</Text>
        <Text style={[styles.footerTitle, isMobile && styles.footerTitleMobile]}>8 New Threat Models{'\n'}Analyzed Today</Text>
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
    lineHeight: 56,
  },
  titleMobile: {
    fontSize: 34,
    lineHeight: 38,
  },
  body: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 18,
    lineHeight: 26,
    maxWidth: 560,
  },
  bodyMobile: {
    fontSize: 15,
    lineHeight: 23,
    maxWidth: undefined,
  },
  grid: {
    gap: 18,
  },
  topGrid: {
    gap: 18,
  },
  topGridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  sideModuleColumn: {
    gap: 18,
  },
  sideModuleColumnDesktop: {
    flex: 1,
  },
  featuredCard: {
    minHeight: 420,
    borderRadius: 36,
    overflow: 'hidden',
    backgroundColor: palette.surfaceLow,
    ...shadows.card,
  },
  featuredCardDesktop: {
    flex: 2,
  },
  featuredCardMobile: {
    minHeight: 360,
    borderRadius: 30,
  },
  featuredImage: {
    ...StyleSheet.absoluteFillObject,
  },
  featuredOverlay: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(16,19,26,0.74)',
  },
  featuredContent: {
    flex: 1,
    padding: 24,
    justifyContent: 'space-between',
    gap: 24,
  },
  featuredContentMobile: {
    padding: 20,
    gap: 18,
  },
  featuredTop: {
    flexDirection: 'row',
    gap: 16,
  },
  featuredTopMobile: {
    flexDirection: 'column',
    gap: 14,
  },
  featuredTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 34,
    lineHeight: 38,
  },
  featuredTitleMobile: {
    fontSize: 24,
    lineHeight: 28,
  },
  featuredBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 16,
    lineHeight: 24,
    marginTop: 10,
  },
  featuredBodyMobile: {
    fontSize: 14,
    lineHeight: 21,
    marginTop: 8,
    maxWidth: 220,
  },
  featuredIcon: {
    width: 76,
    height: 76,
    borderRadius: 26,
    backgroundColor: palette.surfaceHighest,
    alignItems: 'center',
    justifyContent: 'center',
  },
  featuredIconMobile: {
    width: 64,
    height: 64,
    borderRadius: 22,
    alignSelf: 'flex-end',
  },
  progressWrap: {
    gap: 10,
  },
  progressHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  progressLabel: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  progressTrack: {
    height: 10,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.42)',
    overflow: 'hidden',
  },
  progressFill: {
    width: '65%',
    height: '100%',
    backgroundColor: palette.secondary,
    borderRadius: 999,
  },
  ctaButton: {
    alignSelf: 'flex-start',
    borderRadius: 18,
    backgroundColor: palette.primary,
    paddingHorizontal: 20,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  ctaText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  smallCard: {
    backgroundColor: 'rgba(39,45,52,0.78)',
    borderRadius: 36,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 16,
    ...shadows.card,
  },
  smallIconError: {
    width: 56,
    height: 56,
    borderRadius: 20,
    backgroundColor: 'rgba(255,92,82,0.12)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  smallIconPrimary: {
    width: 56,
    height: 56,
    borderRadius: 20,
    backgroundColor: 'rgba(187,198,226,0.14)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  smallTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 28,
  },
  smallTitleMobile: {
    fontSize: 24,
  },
  smallBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  smallBodyMobile: {
    lineHeight: 21,
  },
  lockRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 4,
  },
  lockedText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  disabledButton: {
    borderRadius: 18,
    backgroundColor: palette.surfaceLow,
    paddingVertical: 14,
    alignItems: 'center',
  },
  disabledButtonText: {
    color: 'rgba(196,198,204,0.4)',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  secondaryCta: {
    borderRadius: 18,
    backgroundColor: palette.primary,
    paddingVertical: 14,
    alignItems: 'center',
  },
  secondaryCtaText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  mediumCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 36,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 18,
    gap: 18,
    ...shadows.card,
  },
  mediumCardDesktop: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  mediumCardMobile: {
    borderRadius: 30,
  },
  mediumImage: {
    width: '100%',
    height: 220,
    borderRadius: 24,
  },
  mediumContent: {
    gap: 14,
  },
  advancedBadge: {
    alignSelf: 'flex-start',
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: 'rgba(255,92,82,0.14)',
  },
  advancedBadgeText: {
    color: palette.error,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  mediumTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 32,
  },
  mediumTitleMobile: {
    fontSize: 26,
  },
  mediumBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 15,
    lineHeight: 23,
  },
  mediumBodyMobile: {
    fontSize: 14,
    lineHeight: 21,
  },
  mediumActions: {
    flexDirection: 'row',
    gap: 12,
  },
  lessonWorkspace: {
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.16)',
    backgroundColor: 'rgba(18,23,31,0.82)',
    padding: 24,
    gap: 14,
    ...shadows.card,
  },
  lessonWorkspaceDesktop: {
    flexDirection: 'column',
  },
  lessonWorkspaceHeader: {
    gap: 8,
  },
  lessonWorkspaceEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  lessonWorkspaceTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 30,
    lineHeight: 34,
  },
  lessonWorkspaceTitleMobile: {
    fontSize: 24,
    lineHeight: 28,
  },
  lessonWorkspaceSummary: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
    lineHeight: 22,
  },
  lessonWorkspaceBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  lessonWorkspaceFooter: {
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
  iconButton: {
    width: 52,
    height: 52,
    borderRadius: 18,
    backgroundColor: palette.surfaceHighest,
    alignItems: 'center',
    justifyContent: 'center',
  },
  footer: {
    borderRadius: 36,
    padding: 28,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    backgroundColor: 'rgba(74,225,131,0.06)',
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
    fontSize: 38,
    lineHeight: 42,
    textAlign: 'center',
  },
  footerTitleMobile: {
    fontSize: 28,
    lineHeight: 32,
  },
  pressed: {
    opacity: 0.92,
  },
});
