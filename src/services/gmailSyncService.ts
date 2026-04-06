import { Platform } from 'react-native';
import * as SecureStore from 'expo-secure-store';
import { discovery as googleDiscovery } from 'expo-auth-session/providers/google';
import { refreshAsync, revokeAsync, TokenResponse } from 'expo-auth-session';
import type { TokenType } from 'expo-auth-session';
import { GOOGLE_ANDROID_CLIENT_ID, GOOGLE_IOS_CLIENT_ID, GOOGLE_WEB_CLIENT_ID } from './googleAuthService';

const SECURE_STORE_PREFIX = 'aegis.gmail.mailbox';

export const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
];

export interface GmailMailboxSession {
  email: string;
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  issuedAt?: number;
  expiresIn?: number;
  scope?: string;
  tokenType?: TokenType;
  linkedAt: string;
  lastValidatedAt: string;
}

interface TokenLike {
  accessToken?: string;
  refreshToken?: string;
  idToken?: string;
  issuedAt?: number;
  expiresIn?: number;
  scope?: string;
  tokenType?: TokenType;
}

interface GmailProfileResponse {
  emailAddress: string;
  messagesTotal?: number;
  threadsTotal?: number;
  historyId?: string;
}

const getClientId = () =>
  Platform.select({
    ios: GOOGLE_IOS_CLIENT_ID,
    android: GOOGLE_ANDROID_CLIENT_ID,
    default: GOOGLE_WEB_CLIENT_ID,
  }) || GOOGLE_WEB_CLIENT_ID;

const toMailboxStoreKey = (uid: string, email: string) => `${SECURE_STORE_PREFIX}.${uid}.${encodeURIComponent(email.trim().toLowerCase())}`;

const storeOptions: SecureStore.SecureStoreOptions = {
  keychainService: 'aegis-ai-guard.gmail',
};

const fetchGmailProfile = async (accessToken: string) => {
  const response = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error('Google Gmail access was granted, but the mailbox profile could not be read.');
  }

  const payload = (await response.json()) as GmailProfileResponse;
  if (!payload.emailAddress?.trim()) {
    throw new Error('Google did not return a mailbox address for this account.');
  }

  return payload;
};

const persistSession = async (uid: string, session: GmailMailboxSession) => {
  await SecureStore.setItemAsync(toMailboxStoreKey(uid, session.email), JSON.stringify(session), storeOptions);
};

const toStoredSession = (email: string, authentication: TokenLike, existing?: GmailMailboxSession): GmailMailboxSession => {
  const now = new Date().toISOString();

  return {
    email,
    accessToken: authentication.accessToken || existing?.accessToken || '',
    refreshToken: authentication.refreshToken || existing?.refreshToken,
    idToken: authentication.idToken || existing?.idToken,
    issuedAt: authentication.issuedAt ?? existing?.issuedAt,
    expiresIn: authentication.expiresIn ?? existing?.expiresIn,
    scope: authentication.scope || existing?.scope,
    tokenType: authentication.tokenType || existing?.tokenType,
    linkedAt: existing?.linkedAt || now,
    lastValidatedAt: now,
  };
};

export const getStoredGmailMailboxSession = async (uid: string, email: string) => {
  const storedValue = await SecureStore.getItemAsync(toMailboxStoreKey(uid, email), storeOptions);
  if (!storedValue) {
    return null;
  }

  try {
    return JSON.parse(storedValue) as GmailMailboxSession;
  } catch {
    await SecureStore.deleteItemAsync(toMailboxStoreKey(uid, email), storeOptions);
    return null;
  }
};

export const saveGmailMailboxSession = async (uid: string, authentication: TokenLike) => {
  if (!authentication.accessToken) {
    throw new Error('Google did not return an access token for Gmail synchronization.');
  }

  const profile = await fetchGmailProfile(authentication.accessToken);
  const email = profile.emailAddress.trim().toLowerCase();
  const existing = await getStoredGmailMailboxSession(uid, email);
  const session = toStoredSession(email, authentication, existing ?? undefined);
  await persistSession(uid, session);

  return {
    email,
    profile,
    session,
  };
};

export const syncStoredGmailMailbox = async (uid: string, email: string) => {
  const normalizedEmail = email.trim().toLowerCase();
  const existing = await getStoredGmailMailboxSession(uid, normalizedEmail);
  if (!existing) {
    throw new Error('This Gmail mailbox is not linked on the current device. Reconnect it to continue syncing.');
  }

  let nextAuthentication: TokenLike = existing;

  const tokenResponse = new TokenResponse({
    accessToken: existing.accessToken,
    refreshToken: existing.refreshToken,
    idToken: existing.idToken,
    scope: existing.scope,
    tokenType: existing.tokenType || 'bearer',
    issuedAt: existing.issuedAt,
    expiresIn: existing.expiresIn,
  });

  if (tokenResponse.shouldRefresh()) {
    if (!existing.refreshToken) {
      throw new Error('The saved Gmail access token expired and no refresh token is available. Reconnect the mailbox to continue.');
    }

    const refreshed = await refreshAsync(
      {
        clientId: getClientId(),
        refreshToken: existing.refreshToken,
      },
      googleDiscovery,
    );

    nextAuthentication = {
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken || existing.refreshToken,
      idToken: refreshed.idToken || existing.idToken,
      issuedAt: refreshed.issuedAt,
      expiresIn: refreshed.expiresIn,
      scope: refreshed.scope,
      tokenType: refreshed.tokenType,
    };
  }

  const profile = await fetchGmailProfile(nextAuthentication.accessToken || existing.accessToken);
  const profileEmail = profile.emailAddress.trim().toLowerCase();
  if (profileEmail !== normalizedEmail) {
    throw new Error(`The connected Google account is ${profileEmail}, but this mailbox record is ${normalizedEmail}.`);
  }

  const session = toStoredSession(profileEmail, nextAuthentication, existing);
  await persistSession(uid, session);

  return {
    email: profileEmail,
    profile,
    session,
  };
};

export const removeStoredGmailMailboxSession = async (uid: string, email: string) => {
  const session = await getStoredGmailMailboxSession(uid, email);
  if (!session) {
    return;
  }

  const tokenToRevoke = session.refreshToken || session.accessToken;
  if (tokenToRevoke) {
    try {
      await revokeAsync(
        {
          token: tokenToRevoke,
          clientId: getClientId(),
        },
        googleDiscovery,
      );
    } catch {
      // Best-effort token revocation. Local token cleanup still proceeds.
    }
  }

  await SecureStore.deleteItemAsync(toMailboxStoreKey(uid, email), storeOptions);
};
