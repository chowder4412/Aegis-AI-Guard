import { useEffect, useState } from 'react';
import { ActivityIndicator, Alert, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import * as Clipboard from 'expo-clipboard';
import { BrainCircuit, CheckCircle2, Copy, Globe, Mail, Search, ShieldAlert, Sparkles, X } from 'lucide-react-native';
import { useAcademy } from '../context/AcademyContext';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import { analyzeContent, generateResponse } from '../services/geminiService';
import { submitLearningFeedback } from '../services/learningService';
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

  return (
    <View style={styles.card}>
      <View style={styles.headerRow}>
        <View style={styles.headerIcon}>
          <Sparkles color={palette.secondary} size={18} />
        </View>
        <View>
          <Text style={styles.eyebrow}>AI Manual Scan</Text>
          <Text style={styles.subEyebrow}>
            {type === 'email'
              ? 'Hybrid pipeline: detector + local intelligence first, Gemini copilot when available'
              : 'On-device intelligence first, Gemini copilot when available'}
          </Text>
        </View>
      </View>

      <View style={[styles.scanGrid, isDesktop && styles.scanGridDesktop]}>
        <View style={styles.inputColumn}>
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

          <View style={styles.textareaWrap}>
            {activeScenario ? (
              <View style={styles.drillBanner}>
                <View style={{ flex: 1, gap: 4 }}>
                  <Text style={styles.drillEyebrow}>Academy Scenario</Text>
                  <Text style={styles.drillTitle}>{activeScenario.title}</Text>
                  <Text style={styles.drillBody}>{activeScenario.summary}</Text>
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
              <Text style={styles.emptyText}>Waiting for input analysis</Text>
            </View>
          ) : null}

          {isScanning ? (
            <View style={styles.emptyState}>
              <ActivityIndicator color={palette.secondary} size="large" />
              <Text style={styles.emptyTitle}>{type === 'email' ? 'Running Detection Pipeline' : 'Analyzing Content'}</Text>
              <Text style={styles.emptyText}>
                {type === 'email'
                  ? 'Scoring with the phishing model and local intelligence, then invoking Gemini only when escalation criteria are met...'
                  : 'Running local intelligence engine and optional AI copilot...'}
              </Text>
            </View>
          ) : null}

          {result ? (
            <View style={styles.results}>
              <View style={styles.resultHeader}>
                <View style={[styles.riskBadge, { backgroundColor: riskColors[result.risk].tint }]}>
                  <Text style={[styles.riskBadgeText, { color: riskColors[result.risk].text }]}>{result.risk} Risk</Text>
                </View>
                <Text style={styles.categoryText}>{result.analysisSourceLabel}</Text>
              </View>

              <Text style={styles.categorySubtext}>{result.category}</Text>

              <View style={styles.summaryCard}>
                <Text style={styles.summaryTitle}>{result.summary}</Text>
                <Text style={styles.summaryBody}>{result.detailedSummary}</Text>
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

              <View style={styles.detailBlock}>
                <Text style={styles.detailHeading}>Recommendation</Text>
                <Text style={styles.detailBody}>{result.recommendation}</Text>
              </View>

              {learningMessage ? (
                <View style={styles.learningCard}>
                  <View style={styles.learningHeader}>
                    <BrainCircuit color={palette.secondary} size={16} />
                    <Text style={styles.learningTitle}>Continuous Learning Loop</Text>
                  </View>
                  <Text style={styles.learningBody}>{learningMessage}</Text>
                </View>
              ) : null}

              <View style={styles.detailBlock}>
                <Text style={styles.detailHeading}>Technical Indicators</Text>
                <View style={styles.chipWrap}>
                  {result.technicalDetails.map((detail) => (
                    <View key={detail.label} style={styles.detailChip}>
                      <Text style={styles.detailChipTitle}>{detail.label}</Text>
                      <Text style={styles.detailChipBody}>{detail.description}</Text>
                    </View>
                  ))}
                </View>
              </View>

              <View style={styles.feedbackRow}>
                <Pressable
                  disabled={isSubmittingCorrection}
                  onPress={() => submitCorrection('phishing')}
                  style={({ pressed }) => [styles.feedbackButton, styles.feedbackThreatButton, (pressed || isSubmittingCorrection) && styles.pressed]}
                >
                  <ShieldAlert color={palette.onSecondary} size={14} />
                  <Text style={styles.feedbackThreatText}>Confirm Threat</Text>
                </Pressable>
                <Pressable
                  disabled={isSubmittingCorrection}
                  onPress={() => submitCorrection('legitimate')}
                  style={({ pressed }) => [styles.feedbackButton, styles.feedbackSafeButton, (pressed || isSubmittingCorrection) && styles.pressed]}
                >
                  <CheckCircle2 color={palette.secondary} size={14} />
                  <Text style={styles.feedbackSafeText}>Mark Safe</Text>
                </Pressable>
              </View>

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
    gap: 10,
  },
  detailChip: {
    borderRadius: 18,
    padding: 14,
    backgroundColor: 'rgba(50,53,60,0.22)',
    gap: 6,
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
});
