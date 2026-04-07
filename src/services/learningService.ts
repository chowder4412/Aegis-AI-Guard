import { getCurrentUserIdToken } from '../firebase';
import type { LearningFeedbackPayload, LearningFeedbackResponse } from '../types';
import { getResolvedPhishingApiConfig } from './phishingApiService';

const getLearningBaseUrl = async () => {
  const configured = (await getResolvedPhishingApiConfig()).url.trim();
  if (!configured) {
    return '';
  }

  const base = configured.endsWith('/detect') ? configured.slice(0, -7) : configured;
  return base.replace(/\/$/, '');
};

export const submitLearningFeedback = async (
  payload: LearningFeedbackPayload,
): Promise<LearningFeedbackResponse | null> => {
  const baseUrl = await getLearningBaseUrl();
  if (!baseUrl) {
    return null;
  }

  const token = await getCurrentUserIdToken();
  const response = await fetch(`${baseUrl}/learning/feedback`, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      content: payload.content,
      input_type: payload.inputType,
      source: payload.source,
      feedback_kind: payload.feedbackKind || 'observation',
      risk: payload.risk,
      category: payload.category,
      confidence: payload.confidence,
      summary: payload.summary,
      recommendation: payload.recommendation,
      analysis_source: payload.analysisSource,
      analysis_source_label: payload.analysisSourceLabel,
      lesson_id: payload.lessonId || undefined,
      scenario_id: payload.scenarioId || undefined,
      scenario_title: payload.scenarioTitle || undefined,
      user_label: payload.userLabel || 'unknown',
      signals: payload.signals || [],
    }),
  });

  if (!response.ok) {
    const fallback = 'Unable to queue this scan for continuous learning.';
    try {
      const body = (await response.json()) as { detail?: string };
      throw new Error(body.detail || fallback);
    } catch (error) {
      throw error instanceof Error ? error : new Error(fallback);
    }
  }

  const payloadBody = (await response.json()) as {
    status: 'queued';
    queued_at: string;
    continuous_learning_enabled: boolean;
  };

  return {
    status: payloadBody.status,
    queuedAt: payloadBody.queued_at,
    continuousLearningEnabled: payloadBody.continuous_learning_enabled,
  };
};
