import { useEffect, useMemo, useState } from 'react';
import { Platform, Pressable, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import { ArrowLeft, Bell, CheckCircle2, ChevronRight, Eye, EyeOff, History, Key, Radar, Save } from 'lucide-react-native';
import type { AppTab } from '../components/BottomNavBar';
import { EmailLinker } from '../components/EmailLinker';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { isNativeAuthRuntime } from '../firebase';
import { getStoredGeminiApiKey, setStoredGeminiApiKey } from '../services/geminiService';
import { getResolvedPhishingApiConfig, getStoredPhishingApiUrl, setStoredPhishingApiUrl } from '../services/phishingApiService';
import { getDefaultPreferences, getProtectionGrade, saveUserPreferences, subscribeToUserPreferences } from '../services/securityDataService';
import { fonts, palette, shadows } from '../theme';

interface SettingsProps {
  onBack?: () => void;
  onNavigateTab?: (tab: AppTab) => void;
}

export const Settings = ({ onBack, onNavigateTab }: SettingsProps) => {
  const { isDesktop, isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { isAnyEmailLinked, linkedEmails } = useLinkedEmails();
  const [apiKey, setApiKey] = useState('');
  const [phishingApiUrl, setPhishingApiUrl] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveApiUrlSuccess, setSaveApiUrlSuccess] = useState(false);
  const [advancedExpanded, setAdvancedExpanded] = useState(false);
  const [resolvedApiHint, setResolvedApiHint] = useState('');
  const [preferences, setPreferences] = useState(getDefaultPreferences());

  const updateResolvedApiHint = (url: string, source: 'manual' | 'shared-env' | 'expo-dev' | 'unconfigured') => {
    setResolvedApiHint(
      source === 'manual'
        ? `Manual backend override active: ${url}`
        : source === 'expo-dev'
          ? `Auto-detected dev backend: ${url}`
          : source === 'shared-env'
            ? `Shared default backend: ${url}`
            : '',
    );
  };

  useEffect(() => {
    const hydrate = async () => {
      const [savedKey, savedApiUrl, resolvedApiConfig] = await Promise.all([
        getStoredGeminiApiKey(),
        getStoredPhishingApiUrl(),
        getResolvedPhishingApiConfig(),
      ]);
      setApiKey(savedKey);
      setPhishingApiUrl(savedApiUrl);
      updateResolvedApiHint(resolvedApiConfig.url, resolvedApiConfig.source);
    };
    void hydrate();
  }, []);

  useEffect(() => {
    if (!user) {
      setPreferences(getDefaultPreferences());
      return;
    }

    const unsubscribe = subscribeToUserPreferences(user.uid, setPreferences);
    return unsubscribe;
  }, [user]);

  const handleSaveKey = async () => {
    await setStoredGeminiApiKey(apiKey);
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  const handleSaveApiUrl = async () => {
    await setStoredPhishingApiUrl(phishingApiUrl);
    const resolvedApiConfig = await getResolvedPhishingApiConfig();
    updateResolvedApiHint(resolvedApiConfig.url, resolvedApiConfig.source);
    setSaveApiUrlSuccess(true);
    setTimeout(() => setSaveApiUrlSuccess(false), 2500);
  };

  const handleRealtimeToggle = (value: boolean) => {
    setPreferences((current) => ({ ...current, realtimeEnabled: value }));
    if (user) {
      void saveUserPreferences(user.uid, { realtimeEnabled: value });
    }
  };

  const handleSensitivityChange = (value: 'low' | 'medium' | 'high') => {
    setPreferences((current) => ({ ...current, detectionSensitivity: value }));
    if (user) {
      void saveUserPreferences(user.uid, { detectionSensitivity: value });
    }
  };

  const handleNotificationToggle = (key: keyof typeof preferences.notifications) => {
    const nextNotifications = {
      ...preferences.notifications,
      [key]: !preferences.notifications[key],
    };
    setPreferences((current) => ({ ...current, notifications: nextNotifications }));
    if (user) {
      void saveUserPreferences(user.uid, { notifications: nextNotifications });
    }
  };

  const protectionGrade = useMemo(
    () =>
      getProtectionGrade(
        linkedEmails.length,
        preferences.realtimeEnabled,
        preferences.detectionSensitivity,
        preferences.notifications.criticalAlerts,
      ),
    [linkedEmails.length, preferences],
  );
  const runtimeReadiness = useMemo(
    () => [
      {
        label: 'Runtime',
        value: Platform.OS === 'web' ? 'Hosted/Web' : Platform.OS === 'ios' ? 'iOS' : Platform.OS === 'android' ? 'Android' : Platform.OS,
      },
      {
        label: 'Auth Bridge',
        value: isNativeAuthRuntime ? 'Native Firebase' : 'JS/Auth Session',
      },
      {
        label: 'Phone Auth',
        value: Platform.OS === 'web' ? 'Ready on web' : isNativeAuthRuntime ? 'Ready in dev build' : 'Needs dev build',
      },
      {
        label: 'Mailbox Auto Sweep',
        value: linkedEmails.some((item) => item.provider === 'gmail-oauth') ? 'Active with scheduling' : 'Awaiting Gmail link',
      },
    ],
    [linkedEmails],
  );

  const handleOpenAdvancedConfiguration = () => {
    setAdvancedExpanded(true);
  };

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Pressable onPress={onBack} style={({ pressed }) => [styles.backButton, pressed && styles.pressed]}>
          <ArrowLeft color={palette.primary} size={20} />
        </Pressable>
        <Text style={[styles.headerTitle, isMobile && styles.headerTitleMobile]}>Settings</Text>
      </View>

      <View style={styles.section}>
        <View style={[styles.sectionTitleRow, isMobile && styles.sectionTitleRowMobile]}>
          <Text style={[styles.sectionTitle, isMobile && styles.sectionTitleMobile]}>Account Protection</Text>
          <View style={[styles.protectionBadge, isAnyEmailLinked ? styles.protectedBadge : styles.unprotectedBadge]}>
            <Text style={[styles.protectionText, isAnyEmailLinked ? styles.protectedText : styles.unprotectedText]}>
              {isAnyEmailLinked ? 'Protected' : 'Not Protected'}
            </Text>
          </View>
        </View>
        <EmailLinker />
      </View>

      <View style={styles.section}>
        <Text style={styles.eyebrow}>Security Core</Text>

        <View style={styles.card}>
          <View style={styles.toggleRow}>
            <View style={{ flex: 1 }}>
              <Text style={styles.cardTitle}>Real-time Automatic Threat Detection</Text>
              <Text style={styles.helperText}>
                Automatically intercept and quarantine fraudulent emails the moment they arrive in your inbox.
              </Text>
            </View>
            <Switch
              onValueChange={handleRealtimeToggle}
              thumbColor={preferences.realtimeEnabled ? palette.secondary : '#D9D9D9'}
              value={preferences.realtimeEnabled}
            />
          </View>
        </View>

        <View style={styles.card}>
          <View style={[styles.cardTopRow, isMobile && styles.cardTopRowMobile]}>
            <Text style={styles.cardTitle}>Detection Sensitivity</Text>
            <View style={styles.adaptiveBadge}>
              <Text style={styles.adaptiveBadgeText}>Adaptive AI Active</Text>
            </View>
          </View>

          <View style={styles.sensitivityList}>
            {[
              { id: 'low', title: 'Low Sensitivity', desc: 'Focuses only on high-confidence phishing attempts.' },
              { id: 'medium', title: 'Medium (Standard)', desc: 'Balanced protection using neural behavior analysis.', recommended: true },
              { id: 'high', title: 'High Sensitivity', desc: 'Strictest filtering with more manual review.' },
            ].map((level) => (
              <Pressable
                key={level.id}
                onPress={() => handleSensitivityChange(level.id as 'low' | 'medium' | 'high')}
                style={({ pressed }) => [styles.levelCard, preferences.detectionSensitivity === level.id && styles.levelCardActive, pressed && styles.pressed]}
              >
                {level.recommended ? (
                  <View style={styles.recommendedBadge}>
                    <Text style={styles.recommendedBadgeText}>Recommended</Text>
                  </View>
                ) : null}
                <View style={[styles.radioOuter, preferences.detectionSensitivity === level.id && styles.radioOuterActive]}>
                  {preferences.detectionSensitivity === level.id ? <View style={styles.radioInner} /> : null}
                </View>
                <View style={{ flex: 1 }}>
                  <Text style={styles.levelTitle}>{level.title}</Text>
                  <Text style={styles.levelBody}>{level.desc}</Text>
                </View>
              </Pressable>
            ))}
          </View>
        </View>

        <View style={styles.card}>
          <Pressable onPress={() => setAdvancedExpanded((current) => !current)} style={({ pressed }) => [styles.advancedHeader, pressed && styles.pressed]}>
            <View style={styles.cardHeader}>
              <View style={styles.cardIconPrimary}>
                <Key color={palette.primary} size={18} />
              </View>
              <View style={{ flex: 1 }}>
                <Text style={styles.cardTitle}>Advanced Configuration</Text>
                <Text style={styles.cardSubtitle}>Optional manual overrides</Text>
              </View>
            </View>
            <ChevronRight color={palette.primaryMuted} size={18} style={advancedExpanded ? styles.advancedChevronExpanded : undefined} />
          </Pressable>

          <Text style={styles.helperText}>
            The app already uses the default services configured in environment variables for regular use. Open this only if you want to override endpoints or keys manually.
          </Text>

          {advancedExpanded ? (
            <View style={styles.advancedContent}>
              <View style={styles.advancedCard}>
                <View style={styles.cardHeader}>
                  <View style={styles.cardIconPrimary}>
                    <Radar color={palette.primary} size={18} />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.cardTitle}>Phishing Detector API</Text>
                    <Text style={styles.cardSubtitle}>Decision tree backend endpoint</Text>
                  </View>
                </View>

                <TextInput
                  autoCapitalize="none"
                  keyboardType="url"
                  onChangeText={setPhishingApiUrl}
                  placeholder="http://localhost:8000"
                  placeholderTextColor="rgba(196,198,204,0.35)"
                  style={styles.apiInput}
                  value={phishingApiUrl}
                />

                <View style={styles.saveRow}>
                  <Text style={styles.helperText}>
                    Leave this blank to keep using the shared default endpoint from the app environment. If set, email scans call this URL first using POST `/detect`.
                  </Text>
                  {resolvedApiHint ? <Text style={styles.configHint}>{resolvedApiHint}</Text> : null}
                  <Pressable
                    onPress={handleSaveApiUrl}
                    style={({ pressed }) => [styles.saveButton, saveApiUrlSuccess && styles.saveButtonSuccess, pressed && styles.pressed]}
                  >
                    {saveApiUrlSuccess ? <CheckCircle2 color="#FFFFFF" size={16} /> : <Save color={palette.onSecondary} size={16} />}
                    <Text style={[styles.saveButtonText, saveApiUrlSuccess && { color: '#FFFFFF' }]}>
                      {saveApiUrlSuccess ? 'Saved' : 'Save Endpoint'}
                    </Text>
                  </Pressable>
                </View>
              </View>

              <View style={styles.advancedCard}>
                <View style={styles.cardHeader}>
                  <View style={styles.cardIconPrimary}>
                    <Key color={palette.primary} size={18} />
                  </View>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.cardTitle}>Gemini AI Configuration</Text>
                    <Text style={styles.cardSubtitle}>Core intelligence engine</Text>
                  </View>
                </View>

                <View style={styles.inputWrap}>
                  <TextInput
                    autoCapitalize="none"
                    onChangeText={setApiKey}
                    placeholder="Enter Gemini API Key"
                    placeholderTextColor="rgba(196,198,204,0.35)"
                    secureTextEntry={!showKey}
                    style={styles.apiInput}
                    value={apiKey}
                  />
                  <Pressable onPress={() => setShowKey((current) => !current)} style={styles.eyeButton}>
                    {showKey ? <EyeOff color={palette.primaryMuted} size={18} /> : <Eye color={palette.primaryMuted} size={18} />}
                  </Pressable>
                </View>

                <View style={styles.saveRow}>
                  <Text style={styles.helperText}>
                    Leave this blank to keep using the shared default Gemini key from the app environment. If no shared key is available, the app continues with the on-device local intelligence engine.
                  </Text>
                  <Pressable onPress={handleSaveKey} style={({ pressed }) => [styles.saveButton, saveSuccess && styles.saveButtonSuccess, pressed && styles.pressed]}>
                    {saveSuccess ? <CheckCircle2 color="#FFFFFF" size={16} /> : <Save color={palette.onSecondary} size={16} />}
                    <Text style={[styles.saveButtonText, saveSuccess && { color: '#FFFFFF' }]}>{saveSuccess ? 'Saved' : 'Save Key'}</Text>
                  </Pressable>
                </View>
              </View>
            </View>
          ) : null}
        </View>
      </View>

      <View style={[styles.preferencesGrid, isDesktop && styles.preferencesGridDesktop]}>
        <View style={[styles.gradeCard, isDesktop && styles.preferenceCardDesktop]}>
          <Text style={styles.cardTitle}>Security Level</Text>
          <Text style={styles.cardSubtitle}>Derived from live coverage and settings</Text>
          <View style={styles.gradeRow}>
            <Text style={styles.gradeValue}>{protectionGrade.grade}</Text>
            <Text style={styles.gradeSub}>{isAnyEmailLinked ? 'Operational' : 'Needs mailbox coverage'}</Text>
          </View>
          <View style={styles.gradeTrack}>
            <View style={[styles.gradeFill, { width: `${protectionGrade.progress}%` }]} />
          </View>
        </View>

        <View style={[styles.card, isDesktop && styles.preferenceCardDesktop]}>
          <View style={styles.notificationHeader}>
            <Text style={styles.cardTitle}>Notifications</Text>
            <Bell color={palette.primaryMuted} size={18} />
          </View>
          <View style={styles.notificationList}>
            {[
              { key: 'criticalAlerts', label: 'Critical Alerts', active: preferences.notifications.criticalAlerts },
              { key: 'weeklyReport', label: 'Weekly Report', active: preferences.notifications.weeklyReport },
              { key: 'marketing', label: 'Marketing', active: preferences.notifications.marketing },
            ].map((item) => (
              <Pressable key={item.label} onPress={() => handleNotificationToggle(item.key as keyof typeof preferences.notifications)} style={({ pressed }) => [styles.notificationRow, pressed && styles.pressed]}>
                <Text style={[styles.notificationText, !item.active && styles.notificationTextMuted]}>{item.label}</Text>
                {item.active ? <CheckCircle2 color={palette.secondary} size={18} /> : <View style={styles.notificationCircle} />}
              </Pressable>
            ))}
          </View>
        </View>
      </View>

      <View style={styles.card}>
        <View style={styles.notificationHeader}>
          <Text style={styles.cardTitle}>Runtime Readiness</Text>
          <CheckCircle2 color={palette.secondary} size={18} />
        </View>
        <Text style={styles.helperText}>
          Live diagnostics for the current platform, auth bridge, and mailbox automation path.
        </Text>
        <View style={styles.notificationList}>
          {runtimeReadiness.map((item) => (
            <View key={item.label} style={styles.notificationRow}>
              <Text style={styles.notificationText}>{item.label}</Text>
              <Text style={styles.runtimeValue}>{item.value}</Text>
            </View>
          ))}
          {resolvedApiHint ? <Text style={styles.configHint}>{resolvedApiHint}</Text> : null}
        </View>
      </View>

      <View style={styles.actionsList}>
        {[
          {
            label: 'Security Audit Log',
            icon: History,
            onPress: () => onNavigateTab?.('logs'),
          },
          {
            label: 'Advanced Configuration',
            icon: Key,
            onPress: handleOpenAdvancedConfiguration,
          },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <Pressable key={item.label} onPress={item.onPress} style={({ pressed }) => [styles.actionRow, pressed && styles.pressed]}>
              <View style={styles.actionLeft}>
                <Icon color={palette.primaryMuted} size={18} />
                <Text style={styles.actionText}>{item.label}</Text>
              </View>
              <ChevronRight color={palette.primaryMuted} size={18} />
            </Pressable>
          );
        })}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    gap: 22,
    width: '100%',
    maxWidth: 1200,
    alignSelf: 'center',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 16,
  },
  backButton: {
    width: 46,
    height: 46,
    borderRadius: 18,
    backgroundColor: palette.surfaceHighest,
    alignItems: 'center',
    justifyContent: 'center',
  },
  headerTitle: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 30,
  },
  headerTitleMobile: {
    fontSize: 26,
  },
  section: {
    gap: 16,
  },
  sectionTitleRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
  },
  sectionTitleRowMobile: {
    alignItems: 'flex-start',
    flexWrap: 'wrap',
  },
  sectionTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 34,
  },
  sectionTitleMobile: {
    fontSize: 32,
    lineHeight: 38,
    maxWidth: 260,
  },
  protectionBadge: {
    borderRadius: 12,
    paddingHorizontal: 14,
    paddingVertical: 8,
  },
  protectedBadge: {
    backgroundColor: 'rgba(39,198,122,0.16)',
  },
  unprotectedBadge: {
    backgroundColor: 'rgba(255,92,82,0.16)',
  },
  protectionText: {
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  protectedText: {
    color: palette.success,
  },
  unprotectedText: {
    color: palette.error,
  },
  eyebrow: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  card: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 28,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    gap: 16,
    ...shadows.card,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  cardIconPrimary: {
    width: 42,
    height: 42,
    borderRadius: 16,
    backgroundColor: 'rgba(187,198,226,0.12)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  cardTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 22,
  },
  cardSubtitle: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
    marginTop: 4,
  },
  inputWrap: {
    position: 'relative',
  },
  apiInput: {
    borderRadius: 18,
    backgroundColor: 'rgba(50,53,60,0.3)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    paddingHorizontal: 16,
    paddingVertical: 15,
    paddingRight: 48,
    color: palette.onSurface,
    fontFamily: fonts.body,
    fontSize: 14,
  },
  eyeButton: {
    position: 'absolute',
    right: 14,
    top: 14,
  },
  saveRow: {
    gap: 14,
  },
  helperText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  configHint: {
    color: palette.secondary,
    fontFamily: fonts.bodyMedium,
    fontSize: 13,
    lineHeight: 19,
  },
  saveButton: {
    alignSelf: 'flex-start',
    borderRadius: 16,
    backgroundColor: palette.primary,
    paddingHorizontal: 18,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  saveButtonSuccess: {
    backgroundColor: palette.success,
  },
  saveButtonText: {
    color: '#263046',
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  toggleRow: {
    flexDirection: 'row',
    gap: 14,
    alignItems: 'flex-start',
  },
  advancedHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  advancedChevronExpanded: {
    transform: [{ rotate: '90deg' }],
  },
  advancedContent: {
    gap: 16,
  },
  advancedCard: {
    borderRadius: 22,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.22)',
    backgroundColor: 'rgba(11,14,20,0.22)',
    padding: 16,
    gap: 16,
  },
  cardTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    gap: 12,
  },
  cardTopRowMobile: {
    flexDirection: 'column',
    alignItems: 'flex-start',
  },
  adaptiveBadge: {
    borderRadius: 12,
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: 'rgba(74,225,131,0.12)',
    alignSelf: 'flex-start',
  },
  adaptiveBadgeText: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  sensitivityList: {
    gap: 12,
  },
  levelCard: {
    borderRadius: 22,
    padding: 18,
    backgroundColor: palette.backgroundDeep,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    flexDirection: 'row',
    gap: 14,
    position: 'relative',
  },
  levelCardActive: {
    borderColor: palette.secondary,
    backgroundColor: 'rgba(74,225,131,0.06)',
  },
  recommendedBadge: {
    position: 'absolute',
    right: 16,
    top: -12,
    borderRadius: 999,
    backgroundColor: palette.secondary,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  recommendedBadgeText: {
    color: palette.onSecondary,
    fontFamily: fonts.headlineBold,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  radioOuter: {
    width: 24,
    height: 24,
    borderRadius: 12,
    borderWidth: 2,
    borderColor: palette.primaryMuted,
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 2,
  },
  radioOuterActive: {
    borderColor: palette.secondary,
  },
  radioInner: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: palette.secondary,
  },
  levelTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 18,
  },
  levelBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 21,
    marginTop: 6,
  },
  preferencesGrid: {
    gap: 16,
  },
  preferencesGridDesktop: {
    flexDirection: 'row',
    alignItems: 'stretch',
  },
  preferenceCardDesktop: {
    flex: 1,
  },
  gradeCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 22,
    gap: 12,
    ...shadows.card,
  },
  gradeRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    gap: 10,
    marginTop: 8,
  },
  gradeValue: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 66,
    lineHeight: 68,
  },
  gradeSub: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
    marginBottom: 10,
  },
  gradeTrack: {
    height: 10,
    borderRadius: 999,
    backgroundColor: 'rgba(50,53,60,0.3)',
    overflow: 'hidden',
  },
  gradeFill: {
    width: '85%',
    height: '100%',
    backgroundColor: palette.primary,
    borderRadius: 999,
  },
  notificationHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  notificationList: {
    gap: 14,
  },
  notificationRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  notificationText: {
    color: palette.onSurface,
    fontFamily: fonts.bodyMedium,
    fontSize: 15,
  },
  runtimeValue: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
    maxWidth: '55%',
    textAlign: 'right',
  },
  notificationTextMuted: {
    color: 'rgba(196,198,204,0.44)',
  },
  notificationCircle: {
    width: 18,
    height: 18,
    borderRadius: 9,
    borderWidth: 2,
    borderColor: 'rgba(68,71,76,0.35)',
  },
  actionsList: {
    gap: 12,
  },
  actionRow: {
    borderRadius: 24,
    backgroundColor: palette.surfaceLow,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 20,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    ...shadows.card,
  },
  actionLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 14,
  },
  actionText: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 18,
  },
  pressed: {
    opacity: 0.92,
  },
});
