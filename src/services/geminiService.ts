import AsyncStorage from '@react-native-async-storage/async-storage';
import type { EmailDetectionResponse, ScanResult } from '../types';
import { analyzeContentWithLocalIntelligence, type LocalIntelligenceResult } from './localIntelligenceService';
import { type BackendEmailDetectionResult, detectEmailWithBackendDetailed, getResolvedPhishingApiConfig } from './phishingApiService';

export const GEMINI_API_KEY_STORAGE_KEY = 'aegis.gemini.apiKey';

export const getStoredGeminiApiKey = async () => {
  const storedKey = await AsyncStorage.getItem(GEMINI_API_KEY_STORAGE_KEY);
  return storedKey || process.env.EXPO_PUBLIC_GEMINI_API_KEY || '';
};

export const setStoredGeminiApiKey = async (value: string) => {
  if (!value.trim()) {
    await AsyncStorage.removeItem(GEMINI_API_KEY_STORAGE_KEY);
    return;
  }
  await AsyncStorage.setItem(GEMINI_API_KEY_STORAGE_KEY, value.trim());
};

const clampPercent = (value: number) => {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(value)));
};

const clamp01 = (value: number) => Math.max(0, Math.min(1, value));
const normalizeConfidencePercent = (value: number) => (value <= 1 ? value * 100 : value);

const riskScore: Record<ScanResult['risk'], number> = {
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

const strongerRisk = (first: ScanResult['risk'], second: ScanResult['risk']): ScanResult['risk'] =>
  riskScore[first] >= riskScore[second] ? first : second;

const probabilityToRisk = (probability: number): ScanResult['risk'] => {
  if (probability >= 0.85) {
    return 'Critical';
  }
  if (probability >= 0.65) {
    return 'High';
  }
  if (probability >= 0.4) {
    return 'Medium';
  }
  return 'Low';
};

const emergencyFallbackScan = (content: string, type: 'url' | 'email'): ScanResult => {
  const normalized = content.toLowerCase();
  const suspicious = /(verify|urgent|login|password|bank|click|secure|suspend)/i.test(normalized);
  return {
    summary: suspicious
      ? `The ${type} appears suspicious and should be reviewed before interaction.`
      : `The ${type} appears lower risk but still requires caution.`,
    detailedSummary: 'A minimal fallback evaluator was used because advanced analysis did not complete.',
    confidence: suspicious ? 78 : 62,
    recommendation: suspicious
      ? 'Quarantine and validate sender/domain authenticity before any action.'
      : 'Validate sender/domain authenticity before acting.',
    risk: suspicious ? 'High' : 'Medium',
    category: suspicious ? 'Phishing' : 'Other',
    impactScore: suspicious ? 7.4 : 4.6,
    mitreTechnique: suspicious ? 'T1566.001' : 'T1589.001',
    mitreTactic: suspicious ? 'Initial Access' : 'Reconnaissance',
    technicalDetails: [
      { label: 'Emergency fallback', description: 'Advanced local/Gemini analysis was unavailable for this scan.' },
      { label: 'Keyword match', description: suspicious ? 'Suspicious trigger terms detected in content.' : 'Few explicit trigger terms detected.' },
    ],
    analysisSource: 'fallback',
    analysisSourceLabel: 'Emergency fallback engine',
  };
};

const getPhishingProbability = (payload: EmailDetectionResponse) => {
  const candidate = payload.phishingProbability ?? payload.phishing_probability;
  if (candidate !== undefined && Number.isFinite(candidate)) {
    return candidate <= 1 ? clamp01(Number(candidate)) : clamp01(Number(candidate) / 100);
  }

  const fromConfidence = normalizeConfidencePercent(payload.confidence) / 100;
  return payload.label === 'phishing' ? fromConfidence : 1 - fromConfidence;
};

const shouldEscalateToGemini = (payload: EmailDetectionResponse, localProbability: number) => {
  const backendProbability = getPhishingProbability(payload);
  const confidence = normalizeConfidencePercent(payload.confidence);
  const disagreement = Math.abs(backendProbability - localProbability);

  if (backendProbability >= 0.72 || localProbability >= 0.72) {
    return true;
  }

  if (disagreement >= 0.25) {
    return true;
  }

  if ((backendProbability >= 0.35 && backendProbability <= 0.75) || (localProbability >= 0.35 && localProbability <= 0.75)) {
    return true;
  }

  return confidence >= 45 && confidence <= 85;
};

const parseGeminiResult = (raw: string): ScanResult | null => {
  try {
    const payload = JSON.parse(raw) as Partial<ScanResult>;
    if (!payload || typeof payload !== 'object') {
      return null;
    }

    const risk = payload.risk;
    const category = payload.category;
    if (!risk || !category || !['Critical', 'High', 'Medium', 'Low'].includes(risk) || !['Phishing', 'Malware', 'Spoofing', 'Social', 'Other'].includes(category)) {
      return null;
    }

    const details = Array.isArray(payload.technicalDetails) ? payload.technicalDetails : [];
    const technicalDetails = details
      .map((item) => ({
        label: String((item as { label?: unknown }).label || '').trim(),
        description: String((item as { description?: unknown }).description || '').trim(),
      }))
      .filter((item) => item.label && item.description)
      .slice(0, 4);

    return {
      summary: String(payload.summary || 'Security analysis completed.').trim(),
      detailedSummary: String(payload.detailedSummary || 'Gemini returned a concise assessment.').trim(),
      confidence: clampPercent(normalizeConfidencePercent(Number(payload.confidence ?? 0))),
      recommendation: String(payload.recommendation || 'Review manually before interacting with this content.').trim(),
      risk: risk as ScanResult['risk'],
      category: category as ScanResult['category'],
      impactScore: Number.isFinite(payload.impactScore) ? Number(Number(payload.impactScore).toFixed(1)) : 5,
      mitreTechnique: String(payload.mitreTechnique || 'T1566.001').trim(),
      mitreTactic: String(payload.mitreTactic || 'Initial Access').trim(),
      technicalDetails:
        technicalDetails.length > 0
          ? technicalDetails
          : [{ label: 'Model output', description: 'Gemini returned a result with limited technical detail fields.' }],
      analysisSource: 'gemini',
      analysisSourceLabel: 'Gemini AI analysis',
    };
  } catch {
    return null;
  }
};

const runBackendCopilotAnalysis = async (
  content: string,
  type: 'url' | 'email',
  contextLines: string[] = [],
): Promise<ScanResult | null> => {
  try {
    const config = await getResolvedPhishingApiConfig();
    const baseUrl = config.url.trim().replace(/\/+$/, '');
    if (!baseUrl) {
      return null;
    }

    const response = await fetch(`${baseUrl}/copilot/explain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        content,
        input_type: type,
        summary: contextLines.length > 0 ? contextLines.join(' | ') : undefined,
      }),
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    const risk = (data.risk || 'High') as ScanResult['risk'];
    const category = (data.category || 'Phishing') as ScanResult['category'];
    const confidence = clampPercent(Number(data.confidence ?? 85));
    const technicalDetails =
      Array.isArray(data.technical_details) && data.technical_details.length > 0
        ? data.technical_details.map((item: Record<string, unknown>) => ({
            label: String(item.label || 'Indicator'),
            description: String(item.description || 'Threat detail'),
          }))
        : (data.threat_indicators || []).map((ind: string) => ({
            label: ind,
            description: 'Threat indicator flagged by Aegis Copilot Engine.',
          }));

    return {
      summary: data.summary || 'Copilot security assessment completed.',
      detailedSummary: data.detailed_explanation || 'Copilot analyzed threat indicators and behavioral cues.',
      confidence,
      recommendation: data.recommended_action || 'Quarantine and review item with caution.',
      risk,
      category,
      impactScore:
        typeof data.impact_score === 'number'
          ? data.impact_score
          : risk === 'Critical'
            ? 9.5
            : risk === 'High'
              ? 7.8
              : risk === 'Medium'
                ? 5.2
                : 2.0,
      mitreTechnique: data.mitre_technique || 'T1566.001',
      mitreTactic: data.mitre_tactic || 'Initial Access',
      technicalDetails:
        technicalDetails.length > 0
          ? technicalDetails
          : [{ label: 'Engine assessment', description: 'Heuristic & Copilot review completed.' }],
      analysisSource: 'gemini',
      analysisSourceLabel: data.model ? `Backend Copilot (${data.model})` : 'Backend AI Copilot',
    };
  } catch {
    return null;
  }
};

const buildBackendLocalHybridResult = (
  backendResult: BackendEmailDetectionResult,
  localIntelligence: LocalIntelligenceResult,
): ScanResult => {
  const backendProbability = getPhishingProbability(backendResult.detection);
  const localProbability = clamp01(localIntelligence.phishingProbability);
  const fusedProbability = clamp01(backendProbability * 0.78 + localProbability * 0.22);
  const disagreement = Math.abs(backendProbability - localProbability);

  const phishingDecision =
    fusedProbability >= 0.55 ||
    (backendResult.detection.label === 'phishing' && localProbability >= 0.4) ||
    (disagreement >= 0.3 && Math.max(backendProbability, localProbability) >= 0.7);

  let risk = probabilityToRisk(fusedProbability);
  if (disagreement >= 0.25 && fusedProbability >= 0.35 && riskScore[risk] < riskScore['High']) {
    risk = 'High';
  }

  const category: ScanResult['category'] = phishingDecision
    ? localIntelligence.scanResult.category === 'Spoofing' || backendResult.scanResult.category === 'Spoofing'
      ? 'Spoofing'
      : 'Phishing'
    : disagreement >= 0.25 && localIntelligence.scanResult.category !== 'Other'
      ? localIntelligence.scanResult.category
      : 'Other';

  const confidence = clampPercent((phishingDecision ? fusedProbability : 1 - fusedProbability) * 100);
  const agreementText = disagreement < 0.2 ? 'high alignment' : disagreement < 0.35 ? 'moderate alignment' : 'meaningful disagreement';

  const technicalDetails = [
    {
      label: 'Backend probability',
      description: `Backend model phishing probability: ${Math.round(backendProbability * 100)}% (${backendResult.detection.label}).`,
    },
    {
      label: 'On-device probability',
      description: `Local intelligence phishing probability: ${Math.round(localProbability * 100)}% (score ${localIntelligence.indicatorScore}).`,
    },
    {
      label: 'Model alignment',
      description: `Detector and local engine show ${agreementText}.`,
    },
    ...backendResult.scanResult.technicalDetails,
    ...localIntelligence.scanResult.technicalDetails.map((item) => ({
      label: `Local: ${item.label}`,
      description: item.description,
    })),
  ].slice(0, 7);

  return {
    summary: phishingDecision
      ? 'The email is likely malicious based on detector output plus on-device threat intelligence.'
      : disagreement >= 0.25
        ? 'The email shows mixed signals; manual review is recommended before interacting.'
        : 'The email appears lower risk after detector and on-device intelligence review.',
    detailedSummary: `Backend detector and local intelligence were fused for resilient analysis without requiring cloud AI. ${backendResult.scanResult.detailedSummary}`,
    confidence,
    recommendation: phishingDecision
      ? 'Quarantine this message, verify sender/domain authenticity, and block interaction until investigation is complete.'
      : disagreement >= 0.25
        ? 'Move to manual review, inspect sender headers, and validate links in a safe environment.'
        : 'Proceed cautiously and validate sender identity before taking sensitive actions.',
    risk,
    category,
    impactScore: Number(Math.max(backendResult.scanResult.impactScore, localIntelligence.scanResult.impactScore).toFixed(1)),
    mitreTechnique: localIntelligence.scanResult.mitreTechnique || backendResult.scanResult.mitreTechnique,
    mitreTactic: localIntelligence.scanResult.mitreTactic || backendResult.scanResult.mitreTactic,
    technicalDetails,
    analysisSource: 'hybrid',
    analysisSourceLabel: 'Hybrid AI (Detector + Local Intelligence)',
  };
};

const mergeWithGemini = (base: ScanResult, gemini: ScanResult, label: string): ScanResult => {
  const disagreement = base.category !== gemini.category || base.risk !== gemini.risk;
  const mergedRisk = disagreement ? strongerRisk(strongerRisk(base.risk, gemini.risk), 'High') : strongerRisk(base.risk, gemini.risk);

  return {
    summary:
      mergedRisk === 'High' || mergedRisk === 'Critical'
        ? 'Combined analysis indicates elevated threat risk.'
        : 'Combined analysis suggests lower operational risk with normal caution.',
    detailedSummary: `Base analysis: ${base.detailedSummary} Gemini: ${gemini.detailedSummary}`,
    confidence: clampPercent(disagreement ? base.confidence * 0.65 + gemini.confidence * 0.2 : base.confidence * 0.65 + gemini.confidence * 0.35),
    recommendation: disagreement
      ? 'Signals disagree across engines. Treat this as high-priority review before any interaction.'
      : gemini.recommendation || base.recommendation,
    risk: mergedRisk,
    category:
      base.category === 'Other' && gemini.category !== 'Other'
        ? gemini.category
        : gemini.category === 'Other'
          ? base.category
          : base.category,
    impactScore: Number(Math.max(base.impactScore, gemini.impactScore).toFixed(1)),
    mitreTechnique: gemini.mitreTechnique || base.mitreTechnique,
    mitreTactic: gemini.mitreTactic || base.mitreTactic,
    technicalDetails: [
      ...base.technicalDetails,
      ...gemini.technicalDetails.map((item) => ({
        label: `Gemini: ${item.label}`,
        description: item.description,
      })),
    ].slice(0, 7),
    analysisSource: 'hybrid',
    analysisSourceLabel: label,
  };
};

export const analyzeContent = async (content: string, type: 'url' | 'email'): Promise<ScanResult> => {
  let localIntelligence: LocalIntelligenceResult;
  try {
    localIntelligence = analyzeContentWithLocalIntelligence(content, type);
  } catch {
    return emergencyFallbackScan(content, type);
  }

  const localBaseline = localIntelligence.scanResult;

  if (type === 'email') {
    const backendResult = await detectEmailWithBackendDetailed(content);
    if (backendResult) {
      const backendLocalHybrid = buildBackendLocalHybridResult(backendResult, localIntelligence);
      const shouldUseGemini = shouldEscalateToGemini(backendResult.detection, localIntelligence.phishingProbability);

      if (!shouldUseGemini) {
        return backendLocalHybrid;
      }

      const geminiSecondOpinion = await runBackendCopilotAnalysis(content, type, [
        `Backend phishing probability: ${Math.round(getPhishingProbability(backendResult.detection) * 100)}%`,
        `Local phishing probability: ${Math.round(localIntelligence.phishingProbability * 100)}%`,
        `Backend/local label: ${backendResult.detection.label}`,
      ]);

      if (!geminiSecondOpinion) {
        return {
          ...backendLocalHybrid,
          analysisSourceLabel: `${backendLocalHybrid.analysisSourceLabel} (Copilot offline)`,
        };
      }

      return mergeWithGemini(backendLocalHybrid, geminiSecondOpinion, 'Hybrid AI (Detector + Local + Copilot)');
    }

    const copilotFallback = await runBackendCopilotAnalysis(content, type, [
      `Local phishing probability: ${Math.round(localIntelligence.phishingProbability * 100)}%`,
      `Local category: ${localBaseline.category}`,
    ]);
    if (copilotFallback) {
      return mergeWithGemini(localBaseline, copilotFallback, 'Hybrid AI (Local + Copilot)');
    }

    return localBaseline;
  }

  const copilotResult = await runBackendCopilotAnalysis(content, type, [
    `Local phishing probability: ${Math.round(localIntelligence.phishingProbability * 100)}%`,
    `Local category: ${localBaseline.category}`,
  ]);

  if (copilotResult) {
    return mergeWithGemini(localBaseline, copilotResult, 'Hybrid AI (Local + Copilot)');
  }

  return localBaseline;
};

export const generateResponse = async (threatSummary: string, recommendation: string) => {
  try {
    const config = await getResolvedPhishingApiConfig();
    const baseUrl = config.url.trim().replace(/\/+$/, '');
    if (baseUrl) {
      const response = await fetch(`${baseUrl}/copilot/respond`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threat_summary: threatSummary,
          recommendation,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.draft) {
          return data.draft;
        }
      }
    }
  } catch {
    // fallback below
  }

  return `Security Alert Notification\n\nThreat summary: ${threatSummary}\n\nRecommended action: ${recommendation}\n\nPlease avoid interacting with the message until security has completed validation.`;
};
