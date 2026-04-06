import * as ExpoLinking from 'expo-linking';
import { getResolvedPhishingApiConfig } from './phishingApiService';

export const GMAIL_OAUTH_CALLBACK_PATH = 'oauth/gmail';

export interface GmailOAuthCallbackResult {
  status: 'success' | 'error';
  email?: string;
  error?: string;
}

const normalizeBaseUrl = (value: string) => value.trim().replace(/\/$/, '');

export const getConfiguredGmailOAuthUrl = () => normalizeBaseUrl(process.env.EXPO_PUBLIC_GMAIL_OAUTH_URL || '');

export const getGmailOAuthRedirectUri = () => ExpoLinking.createURL(GMAIL_OAUTH_CALLBACK_PATH);

export const buildGmailOAuthStartUrl = async (uid: string) => {
  const explicitBaseUrl = getConfiguredGmailOAuthUrl();
  const resolvedBackendUrl = normalizeBaseUrl((await getResolvedPhishingApiConfig()).url);
  const baseUrl = explicitBaseUrl || (resolvedBackendUrl ? `${resolvedBackendUrl}/oauth/gmail/start` : '');
  if (!baseUrl) {
    return '';
  }

  const redirectUri = getGmailOAuthRedirectUri();
  const url = new URL(baseUrl);
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('uid', uid);
  return url.toString();
};

export const parseGmailOAuthCallback = (url: string): GmailOAuthCallbackResult | null => {
  const parsed = ExpoLinking.parse(url);
  const normalizedPath = (parsed.path?.replace(/^\/+/, '').replace(/^--\//, '') || '').trim();

  if (normalizedPath !== GMAIL_OAUTH_CALLBACK_PATH) {
    return null;
  }

  const statusValue = typeof parsed.queryParams?.status === 'string' ? parsed.queryParams.status : '';
  const emailValue =
    typeof parsed.queryParams?.email === 'string'
      ? parsed.queryParams.email
      : typeof parsed.queryParams?.mailbox === 'string'
        ? parsed.queryParams.mailbox
        : undefined;
  const errorValue =
    typeof parsed.queryParams?.error === 'string'
      ? parsed.queryParams.error
      : typeof parsed.queryParams?.message === 'string'
        ? parsed.queryParams.message
        : undefined;

  if (statusValue === 'success') {
    return {
      status: 'success',
      email: emailValue?.trim().toLowerCase(),
    };
  }

  if (statusValue === 'error') {
    return {
      status: 'error',
      error: errorValue || 'OAuth mailbox linking failed.',
    };
  }

  return null;
};
