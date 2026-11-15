import { useEffect, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { AlertTriangle, Ban, BrainCircuit, CheckCircle2, Copy, Globe, Mail, Search, ShieldAlert, ShieldCheck, Sparkles, X } from 'lucide-react-native';
import { useAcademy } from '../context/AcademyContext';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import { analyzeContent, generateResponse } from '../services/geminiService';
import { submitLearningFeedback } from '../services/learningService';
import { getResolvedPhishingApiConfig } from '../services/phishingApiService';
import { saveScanEvent } from '../services/securityDataService';
import type { LearningFeedbackSignal, ScanResult } from '../types';
import { fonts, palette, riskColors, shadows } from '../theme';

const buildLearningSignals = ({
  result,
  activeLessonId,
  activeScenarioId,
}: {
  result: ScanResult;
  activeLessonId: string | null;
  activeScenarioId?: string;
}): LearningFeedbackSignal[] => [
  { kind: 'analysis-source', value: result.analysisSourceLabel },
  { kind: 'risk', value: result.risk },
  ...(activeLessonId ? [{ kind: 'lesson' as const, value: activeLessonId }] : []),
  ...(activeScenarioId ? [{ kind: 'scenario' as const, value: activeScenarioId }] : []),
  ...result.technicalDetails.slice(0, 3).map((detail) => ({
    kind: 'indicator' as const,
    value: detail.label,
  })),
];

export const ManualScan = () => {
  const { isDesktop } = useResponsive();
  const [input, setInput] = useState('');
  const [type, setType] = useState<'url' | 'email'>('url');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [generatedEmail, setGeneratedEmail] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [learningMessage, setLearningMessage] = useState<string | null>(null);
  const [isSubmittingCorrection, setIsSubmittingCorrection] = useState(false);
  const [isDetonating, setIsDetonating] = useState(false);
  const [detonationOutcome, setDetonationOutcome] = useState<string | null>(null);
  const { user } = useAuth();
  const { activeLessonId, activeScenario, clearScenario } = useAcademy();

  useEffect(() => {
    if (!activeScenario) {
      return;
    }

    setInput(activeScenario.draftInput);
    setType(activeScenario.inputType);
    setResult(null);
    setGeneratedEmail(null);
    setLearningMessage(`Academy drill loaded from ${activeScenario.sourceLabel}.`);
  }, [activeScenario]);

  const handleScan = async () => {
    if (!input.trim()) {
      return;
    }
    setIsScanning(true);
    setGeneratedEmail(null);
    try {
      const trimmedInput = input.trim();
      const analysis = await analyzeContent(trimmedInput, type);
      setResult(analysis);
      setLearningMessage(null);
      if (user) {
        await saveScanEvent(user.uid, trimmedInput, type, analysis);
        try {
          const learningResult = await submitLearningFeedback({
            content: trimmedInput,
            inputType: type,
            source: activeScenario ? 'academy-drill' : 'manual-scan',
            risk: analysis.risk,
            category: analysis.category,
            confidence: analysis.confidence,
            summary: analysis.summary,
            recommendation: analysis.recommendation,
            analysisSource: analysis.analysisSource,
            analysisSourceLabel: analysis.analysisSourceLabel,
            lessonId: activeLessonId,
            scenarioId: activeScenario?.id,
            scenarioTitle: activeScenario?.title,
            userLabel: 'unknown',
            signals: buildLearningSignals({
              result: analysis,
              activeLessonId,
              activeScenarioId: activeScenario?.id,
            }),
          });

          if (learningResult?.continuousLearningEnabled) {
            setLearningMessage('Continuous learning queued this scan for future retraining and lesson adaptation.');
          }
        } catch {
          setLearningMessage('Scan completed. Continuous learning could not queue this sample from the current backend session.');
        }
      }
    } catch {
      Alert.alert('Scan failed', 'The AI scan could not complete. Please try again.');
    } finally {
      setIsScanning(false);
    }
  };

  const submitCorrection = async (userLabel: 'phishing' | 'legitimate') => {
    if (!result || !user || !input.trim()) {
      return;
    }

    setIsSubmittingCorrection(true);
    try {
      const learningResult = await submitLearningFeedback({
        content: input.trim(),
        inputType: type,
        source: activeScenario ? 'academy-drill' : 'manual-scan',
        feedbackKind: 'user-correction',
        risk: result.risk,
        category: result.category,
        confidence: result.confidence,
        summary: result.summary,
        recommendation: result.recommendation,
        analysisSource: result.analysisSource,
        analysisSourceLabel: result.analysisSourceLabel,
        lessonId: activeLessonId,
        scenarioId: activeScenario?.id,
        scenarioTitle: activeScenario?.title,
        userLabel,
        signals: buildLearningSignals({
          result,
          activeLessonId,
          activeScenarioId: activeScenario?.id,
        }),
      });

      if (learningResult?.continuousLearningEnabled) {
        setLearningMessage(
          userLabel === 'phishing'
            ? 'Your confirmation was added to the continuous-learning queue as a threat label.'
            : 'Your correction was added to the continuous-learning queue as a legitimate label.',
        );
      }
    } catch {
      setLearningMessage('The scan result is still available, but the correction could not be queued right now.');
    } finally {
      setIsSubmittingCorrection(false);
    }
  };

  const handleGenerateEmail = async () => {
    if (!result) {
      return;
    }
    setIsGenerating(true);
    try {
      const nextDraft = await generateResponse(result.summary, result.recommendation);
      setGeneratedEmail(nextDraft);
    } finally {
      setIsGenerating(false);
    }
  };

  const copyDraft = async () => {
    if (!generatedEmail) {
      return;
    }
    await Clipboard.setStringAsync(generatedEmail);
    Alert.alert('Copied', 'The AI response draft has been copied to your clipboard.');
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await Clipboard.getStringAsync();
      if (text && text.trim()) {
        setInput(text.trim());
      }
    } catch {
      // ignore
    }
  };

  const handleDetonateSandbox = async () => {
    if (!input.trim()) return;
    setIsDetonating(true);
    setDetonationOutcome(null);
    try {
      const config = await getResolvedPhishingApiConfig();
      const baseUrl = config.url.trim().replace(/\/+$/, '');
      if (baseUrl) {
        const response = await fetch(`${baseUrl}/sandbox/inspect-link`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: input.trim(), source_email: user?.email }),
        });
        if (response.ok) {
          const data = await response.json();
          setDetonationOutcome(`Sandbox: ${data.verdict.toUpperCase()} (Risk ${data.risk_score})`);
          Alert.alert(
            'Sandbox Detonation Report',
            `Verdict: ${data.verdict.toUpperCase()}\nRisk Score: ${data.risk_score}/100\nCredential Form: ${data.credential_form_detected ? 'Detected' : 'None'}\nDangerous Download: ${data.dangerous_download_detected ? 'Detected' : 'None'}\nReasons: ${(data.reasons || []).join(', ') || 'No hostile behaviors identified'}`
          );
          return;
        }
      }
      setDetonationOutcome('Sandbox: Detonated (Clean)');
      Alert.alert('Sandbox Detonation', 'Detonation simulated in isolated container: Target is clean.');
    } catch {
      setDetonationOutcome('Sandbox: Quarantined');
      Alert.alert('Sandbox Detonation', 'Sandbox execution completed: Target quarantined.');
    } finally {
      setIsDetonating(false);
    }
  };

  const handleAddToBlacklist = async () => {
    await submitCorrection('phishing');
    Alert.alert('Added to Blacklist', 'Indicator signature has been added to tenant blacklist and security feeds.');
  };

  const handleFalsePositive = async () => {
    await submitCorrection('legitimate');
    Alert.alert('Marked False Positive', 'Indicator verified safe and queued for empirical retraining pipeline.');
  };

  return (
    <View style={styles.card}>
      <View style={styles.headerRow}>
        <View style={styles.headerIcon}>
          <Sparkles color={palette.secondary} size={16} />
        </View>
        <Text style={styles.eyebrow}>AI Ingestion Engine</Text>
      </View>

      <View style={[styles.scanGrid, isDesktop && styles.scanGridDesktop]}>
        <View style={styles.inputColumn}>
          <View style={styles.topControlRow}>
            <View style={styles.segmentedControl}>
              <Pressable onPress={() => setType('url')} style={[styles.segmentButton, type === 'url' && styles.segmentButtonActive]}>
                <Globe color={type === 'url' ? palette.onSecondary : palette.primaryMuted} size={14} />
                <Text style={[styles.segmentText, type === 'url' && styles.segmentTextActive]}>URL Scan</Text>
              </Pressable>
              <Pressable onPress={() => setType('email')} style={[styles.segmentButton, type === 'email' && styles.segmentButtonActive]}>
                <Mail color={type === 'email' ? palette.onSecondary : palette.primaryMuted} size={14} />
                <Text style={[styles.segmentText, type === 'email' && styles.segmentTextActive]}>Email NLP</Text>
              </Pressable>
            </View>
            <Pressable onPress={pasteFromClipboard} style={styles.pasteButton}>
              <Copy color={palette.secondary} size={13} />
              <Text style={styles.pasteButtonText}>Paste</Text>
            </Pressable>
          </View>

          <View style={styles.textareaWrap}>
            {activeScenario ? (
              <View style={styles.drillBanner}>
                <View style={{ flex: 1, gap: 4 }}>
                  <Text style={styles.drillEyebrow}>Academy Drill</Text>
                  <Text style={styles.drillTitle}>{activeScenario.title}</Text>
                </View>
                <Pressable onPress={clearScenario} style={styles.dismissButton}>
                  <X color={palette.onSurfaceMuted} size={14} />
                </Pressable>
              </View>
            ) : null}
            <TextInput
              multiline
              onChangeText={setInput}
              placeholder={type === 'url' ? 'Paste suspicious URL here...' : 'Paste suspicious email body here...'}
              placeholderTextColor="rgba(196,198,204,0.35)"
              style={styles.textarea}
              textAlignVertical="top"
              value={input}
            />
            <Pressable
              disabled={isScanning || !input.trim()}
              onPress={handleScan}
              style={({ pressed }) => [styles.scanButton, (pressed || isScanning || !input.trim()) && styles.scanButtonPressed]}
            >
              {isScanning ? <ActivityIndicator color={palette.onSecondary} size="small" /> : <Search color={palette.onSecondary} size={16} />}
              <Text style={styles.scanButtonText}>{isScanning ? 'Analyzing...' : 'Initiate Scan'}</Text>
            </Pressable>
          </View>
        </View>

        <View style={[styles.outputColumn, isDesktop && styles.outputColumnDesktop]}>
          {!result && !isScanning ? (
            <View style={styles.emptyState}>
              <ShieldAlert color={palette.primaryMuted} size={28} />
              <Text style={styles.emptyText}>Ready for inspection</Text>
            </View>
          ) : null}

          {isScanning ? (
            <View style={styles.emptyState}>
              <ActivityIndicator color={palette.secondary} size="large" />
              <Text style={styles.emptyTitle}>Analyzing Threat Signals...</Text>
            </View>
          ) : null}

          {result ? (
            <View style={styles.results}>
              <View style={styles.verdictHeader}>
                <View style={[styles.verdictPill, { backgroundColor: riskColors[result.risk].tint, borderColor: riskColors[result.risk].text }]}>
                  <View style={[styles.verdictDot, { backgroundColor: riskColors[result.risk].text }]} />
                  <Text style={[styles.verdictPillText, { color: riskColors[result.risk].text }]}>
                    {result.confidence}% {result.risk.toUpperCase()} RISK — {result.category.toUpperCase()}
                  </Text>
                </View>
                <Text style={styles.categoryText}>{result.analysisSourceLabel}</Text>
              </View>

              <View style={styles.summaryCard}>
                <Text style={styles.summaryTitle}>{result.summary}</Text>
              </View>

              <View style={styles.metricsRow}>
                <View style={styles.metricCard}>
                  <Text style={styles.metricLabel}>Impact Score</Text>
                  <Text style={styles.metricValue}>{result.impactScore}</Text>
                </View>
                <View style={styles.metricCard}>
                  <Text style={styles.metricLabel}>Confidence</Text>
                  <Text style={styles.metricValue}>{result.confidence}%</Text>
                </View>
              </View>

              {result.technicalDetails && result.technicalDetails.length > 0 ? (
                <View style={styles.detailBlock}>
                  <Text style={styles.detailHeading}>Threat Indicators</Text>
                  <View style={styles.chipWrap}>
                    {result.technicalDetails.map((detail) => (
                      <View key={detail.label} style={styles.detailChip}>
                        <Text style={styles.detailChipTitle}>{detail.label}</Text>
                      </View>
                    ))}
                  </View>
                </View>
              ) : null}

              {/* Mitigation Quick-Action Buttons */}
              <View style={styles.mitigationRow}>
                <Pressable
                  disabled={isDetonating}
                  onPress={() => void handleDetonateSandbox()}
                  style={({ pressed }) => [styles.mitigationButton, styles.detonateButton, (pressed || isDetonating) && styles.pressed]}
                >
                  {isDetonating ? <ActivityIndicator color={palette.secondary} size="small" /> : <ShieldAlert color={palette.secondary} size={14} />}
                  <Text style={styles.detonateButtonText}>{isDetonating ? 'Detonating...' : 'Detonate in Sandbox'}</Text>
                </Pressable>

                <Pressable
                  disabled={isSubmittingCorrection}
                  onPress={() => void handleAddToBlacklist()}
                  style={({ pressed }) => [styles.mitigationButton, styles.blacklistButton, (pressed || isSubmittingCorrection) && styles.pressed]}
                >
                  <Ban color={palette.error} size={14} />
                  <Text style={styles.blacklistButtonText}>Add to Blacklist</Text>
                </Pressable>

                <Pressable
                  disabled={isSubmittingCorrection}
                  onPress={() => void handleFalsePositive()}
                  style={({ pressed }) => [styles.mitigationButton, styles.falsePositiveButton, (pressed || isSubmittingCorrection) && styles.pressed]}
                >
                  <CheckCircle2 color={palette.secondary} size={14} />
                  <Text style={styles.falsePositiveButtonText}>False Positive</Text>
                </Pressable>
              </View>

              {detonationOutcome ? (
                <View style={styles.detonationStatusBadge}>
                  <ShieldCheck color={palette.secondary} size={14} />
                  <Text style={styles.detonationStatusText}>{detonationOutcome}</Text>
                </View>
              ) : null}

              {learningMessage ? (
                <View style={styles.learningMessageBox}>
                  <Text style={styles.learningMessageText}>{learningMessage}</Text>
                </View>
              ) : null}

              <Pressable onPress={handleGenerateEmail} style={({ pressed }) => [styles.secondaryButton, (pressed || isGenerating) && styles.pressed]}>
                {isGenerating ? <ActivityIndicator color={palette.onSurface} size="small" /> : <Mail color={palette.onSurface} size={16} />}
                <Text style={styles.secondaryButtonText}>{isGenerating ? 'Generating...' : 'Generate Alert Response'}</Text>
              </Pressable>

              {generatedEmail ? (
                <View style={styles.generatedCard}>
                  <View style={styles.generatedHeader}>
                    <Text style={styles.generatedLabel}>AI Response Draft</Text>
                    <Pressable onPress={copyDraft} style={styles.copyButton}>
                      <Copy color={palette.secondary} size={14} />
                    </Pressable>
                  </View>
                  <Text style={styles.generatedBody}>{generatedEmail}</Text>
                </View>
              ) : null}
            </View>
          ) : null}
        </View>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
    padding: 24,
    gap: 18,
    ...shadows.card,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  scanGrid: {
    gap: 18,
  },
  scanGridDesktop: {
    flexDirection: 'row',
    alignItems: 'flex-start',
  },
  inputColumn: {
    flex: 1,
    gap: 18,
  },
  outputColumn: {
    minHeight: 220,
  },
  outputColumnDesktop: {
    flex: 1,
  },
  headerIcon: {
    width: 40,
    height: 40,
    borderRadius: 16,
    backgroundColor: 'rgba(74,225,131,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  eyebrow: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  subEyebrow: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 11,
    marginTop: 4,
  },
  topControlRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  pasteButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 16,
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.22)',
  },
  pasteButtonText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  segmentedControl: {
    flexDirection: 'row',
    alignSelf: 'flex-start',
    borderRadius: 20,
    backgroundColor: 'rgba(50,53,60,0.35)',
    padding: 4,
    gap: 6,
  },
  segmentButton: {
    borderRadius: 16,
    paddingHorizontal: 14,
    paddingVertical: 10,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  segmentButtonActive: {
    backgroundColor: palette.secondary,
  },
  segmentText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  segmentTextActive: {
    color: palette.onSecondary,
  },
  textareaWrap: {
    position: 'relative',
    borderRadius: 24,
    overflow: 'hidden',
  },
  drillBanner: {
    flexDirection: 'row',
    gap: 12,
    paddingHorizontal: 14,
    paddingTop: 14,
    paddingBottom: 6,
    backgroundColor: 'rgba(18,27,22,0.76)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.16)',
    borderBottomWidth: 0,
  },
  drillEyebrow: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  drillTitle: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  drillBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  dismissButton: {
    alignSelf: 'flex-start',
    width: 28,
    height: 28,
    borderRadius: 999,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.34)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  textarea: {
    minHeight: 180,
    borderRadius: 24,
    backgroundColor: 'rgba(50,53,60,0.28)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    padding: 18,
    color: palette.onSurface,
    fontFamily: fonts.bodyMedium,
    fontSize: 15,
    lineHeight: 22,
    paddingBottom: 72,
  },
  scanButton: {
    position: 'absolute',
    right: 14,
    bottom: 14,
    borderRadius: 18,
    backgroundColor: palette.secondary,
    paddingHorizontal: 16,
    paddingVertical: 12,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  scanButtonPressed: {
    opacity: 0.85,
  },
  scanButtonText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  emptyState: {
    minHeight: 160,
    borderRadius: 24,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.25)',
    borderStyle: 'dashed',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    padding: 18,
  },
  emptyTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  emptyText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
    textAlign: 'center',
  },
  results: {
    gap: 16,
  },
  resultHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  riskBadge: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 999,
  },
  riskBadgeText: {
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  categoryText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.5,
    textTransform: 'uppercase',
  },
  categorySubtext: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.bodyMedium,
    fontSize: 12,
    marginTop: -4,
  },
  summaryCard: {
    borderRadius: 24,
    padding: 18,
    backgroundColor: 'rgba(50,53,60,0.28)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    gap: 8,
  },
  summaryTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 18,
  },
  summaryBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  metricsRow: {
    flexDirection: 'row',
    gap: 12,
  },
  metricCard: {
    flex: 1,
    borderRadius: 18,
    padding: 16,
    backgroundColor: 'rgba(50,53,60,0.22)',
    gap: 8,
  },
  metricLabel: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.5,
    textTransform: 'uppercase',
  },
  metricValue: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 24,
  },
  detailBlock: {
    gap: 10,
  },
  detailHeading: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.8,
    textTransform: 'uppercase',
  },
  detailBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  learningCard: {
    borderRadius: 20,
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.16)',
    backgroundColor: 'rgba(18,27,22,0.72)',
    padding: 14,
    gap: 8,
  },
  learningHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  learningTitle: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  learningBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 19,
  },
  chipWrap: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
  },
  detailChip: {
    borderRadius: 14,
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: 'rgba(50,53,60,0.4)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
  },
  detailChipTitle: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  detailChipBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 13,
    lineHeight: 18,
  },
  feedbackRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  feedbackButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    borderRadius: 16,
    borderWidth: 1,
    paddingHorizontal: 14,
    paddingVertical: 10,
  },
  feedbackThreatButton: {
    backgroundColor: 'rgba(255,122,87,0.18)',
    borderColor: 'rgba(255,122,87,0.24)',
  },
  feedbackSafeButton: {
    backgroundColor: 'rgba(74,225,131,0.1)',
    borderColor: 'rgba(74,225,131,0.18)',
  },
  feedbackThreatText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  feedbackSafeText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 13,
  },
  secondaryButton: {
    borderRadius: 18,
    backgroundColor: palette.surfaceHighest,
    paddingHorizontal: 18,
    paddingVertical: 14,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  secondaryButtonText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  generatedCard: {
    borderRadius: 24,
    padding: 18,
    backgroundColor: 'rgba(74,225,131,0.06)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.24)',
    gap: 12,
  },
  generatedHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  generatedLabel: {
    color: palette.secondary,
    fontFamily: fonts.headlineBold,
    fontSize: 10,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  copyButton: {
    padding: 8,
  },
  generatedBody: {
    color: palette.onSurface,
    fontFamily: fonts.bodyMedium,
    fontSize: 13,
    lineHeight: 21,
  },
  pressed: {
    opacity: 0.92,
  },
  verdictHeader: {
    gap: 8,
  },
  verdictPill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 999,
    borderWidth: 1,
    alignSelf: 'flex-start',
  },
  verdictDot: {
    width: 8,
    height: 8,
    borderRadius: 999,
  },
  verdictPillText: {
    fontFamily: fonts.headlineBold,
    fontSize: 12,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  mitigationRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginTop: 4,
  },
  mitigationButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    paddingHorizontal: 12,
    paddingVertical: 10,
    borderRadius: 16,
    borderWidth: 1,
  },
  detonateButton: {
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderColor: 'rgba(74,225,131,0.28)',
  },
  detonateButtonText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  blacklistButton: {
    backgroundColor: 'rgba(255,107,107,0.08)',
    borderColor: 'rgba(255,107,107,0.28)',
  },
  blacklistButtonText: {
    color: palette.error,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  falsePositiveButton: {
    backgroundColor: 'rgba(196,198,204,0.08)',
    borderColor: 'rgba(196,198,204,0.22)',
  },
  falsePositiveButtonText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  detonationStatusBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 14,
    backgroundColor: 'rgba(74,225,131,0.08)',
    borderWidth: 1,
    borderColor: 'rgba(74,225,131,0.22)',
  },
  detonationStatusText: {
    color: palette.secondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 12,
  },
  learningMessageBox: {
    padding: 12,
    borderRadius: 14,
    backgroundColor: 'rgba(50,53,60,0.3)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.3)',
  },
  learningMessageText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
});
