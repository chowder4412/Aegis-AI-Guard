import 'react-native-get-random-values';
import 'react-native-url-polyfill/auto';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Platform } from 'react-native';
import { getApp, getApps, initializeApp } from 'firebase/app';
import {
  browserLocalPersistence,
  createUserWithEmailAndPassword as createWebUserWithEmailAndPassword,
  getAuth,
  getReactNativePersistence,
  GoogleAuthProvider,
  initializeAuth,
  onAuthStateChanged as onWebAuthStateChanged,
  OAuthProvider,
  RecaptchaVerifier,
  setPersistence,
  signInWithCredential as signInWithWebCredential,
  signInWithEmailAndPassword as signInWithWebEmailAndPassword,
  signInWithPhoneNumber as signInWithWebPhoneNumber,
  signInWithPopup,
  signOut as signOutWeb,
  updateProfile as updateWebProfile,
} from 'firebase/auth';
import { collection, addDoc, deleteDoc, doc, getDoc, getFirestore, limit, onSnapshot, orderBy, query, setDoc, updateDoc, Timestamp } from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';

export interface AppAuthUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  emailVerified?: boolean;
  getIdToken: (forceRefresh?: boolean) => Promise<string>;
  getIdTokenResult?: (forceRefresh?: boolean) => Promise<{ claims: Record<string, unknown> }>;
  updateProfile?: (profile: { displayName?: string | null; photoURL?: string | null }) => Promise<void>;
}

export interface AppUserCredential {
  user: AppAuthUser;
}

export interface ConfirmationResult {
  confirm: (verificationCode: string) => Promise<AppUserCredential>;
}

type AuthStateListener = (user: AppAuthUser | null) => void;

const app = getApps().length ? getApp() : initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);

const createWebAuth = () => {
  if (Platform.OS === 'web') {
    const authInstance = getAuth(app);
    void setPersistence(authInstance, browserLocalPersistence).catch(() => undefined);
    return authInstance;
  }

  try {
    return initializeAuth(app, {
      persistence: getReactNativePersistence(AsyncStorage),
    });
  } catch {
    return getAuth(app);
  }
};

const webAuth = createWebAuth();
export const auth = webAuth;

let nativeAuthModuleCache: any = null;
let nativeAuthBridgeCheck: boolean | null = null;

const getNativeAuthModule = () => {
  if (Platform.OS === 'web') {
    return null;
  }

  if (!nativeAuthModuleCache) {
    nativeAuthModuleCache = require('@react-native-firebase/auth').default;
  }

  return nativeAuthModuleCache;
};

const getNativeAuth = () => {
  try {
    const nativeAuthModule = getNativeAuthModule();
    return nativeAuthModule ? nativeAuthModule() : null;
  } catch {
    return null;
  }
};

const detectNativeAuthBridge = () => {
  if (Platform.OS === 'web') {
    return false;
  }
  if (nativeAuthBridgeCheck !== null) {
    return nativeAuthBridgeCheck;
  }

  try {
    nativeAuthBridgeCheck = Boolean(getNativeAuth());
  } catch {
    nativeAuthBridgeCheck = false;
  }
  return nativeAuthBridgeCheck;
};

export const isNativeAuthRuntime = detectNativeAuthBridge();

const normalizeUser = (user: any): AppAuthUser => ({
  uid: user.uid,
  email: user.email ?? null,
  displayName: user.displayName ?? null,
  photoURL: user.photoURL ?? null,
  emailVerified: user.emailVerified,
  getIdToken: (forceRefresh?: boolean) => user.getIdToken(forceRefresh),
  getIdTokenResult: user.getIdTokenResult ? (forceRefresh?: boolean) => user.getIdTokenResult(forceRefresh) : undefined,
  updateProfile: user.updateProfile ? (profile) => user.updateProfile(profile) : undefined,
});

const normalizeUserCredential = (credential: any): AppUserCredential => ({
  user: normalizeUser(credential.user),
});

const normalizeConfirmationResult = (result: any): ConfirmationResult => ({
  confirm: async (verificationCode: string) => normalizeUserCredential(await result.confirm(verificationCode)),
});

export const getCurrentAuthUser = (): AppAuthUser | null => {
  const currentUser = isNativeAuthRuntime ? getNativeAuth()?.currentUser : webAuth.currentUser;
  return currentUser ? normalizeUser(currentUser) : null;
};

export const subscribeToAuthState = (listener: AuthStateListener) => {
  if (isNativeAuthRuntime) {
    const nativeAuth = getNativeAuth();
    return nativeAuth ? nativeAuth.onAuthStateChanged((user: any) => listener(user ? normalizeUser(user) : null)) : () => undefined;
  }

  return onWebAuthStateChanged(webAuth, (user) => listener(user ? normalizeUser(user) : null));
};

export const getCurrentUserIdToken = async () => {
  const currentUser = getCurrentAuthUser();
  if (!currentUser) {
    throw new Error('Sign in before calling protected backend mailbox operations.');
  }

  return currentUser.getIdToken();
};

export const signInWithEmailPassword = async (email: string, password: string): Promise<AppUserCredential> => {
  if (isNativeAuthRuntime) {
    return normalizeUserCredential(await getNativeAuth()!.signInWithEmailAndPassword(email, password));
  }

  return normalizeUserCredential(await signInWithWebEmailAndPassword(webAuth, email, password));
};

export const createUserWithEmailPassword = async (email: string, password: string): Promise<AppUserCredential> => {
  if (isNativeAuthRuntime) {
    return normalizeUserCredential(await getNativeAuth()!.createUserWithEmailAndPassword(email, password));
  }

  return normalizeUserCredential(await createWebUserWithEmailAndPassword(webAuth, email, password));
};

export const signOutCurrentUser = async () => {
  if (isNativeAuthRuntime) {
    await getNativeAuth()!.signOut();
    return;
  }

  await signOutWeb(webAuth);
};

export const updateCurrentUserProfile = async (profile: { displayName?: string | null; photoURL?: string | null }) => {
  const currentUser = getCurrentAuthUser();
  if (!currentUser) {
    return;
  }

  if (isNativeAuthRuntime) {
    await getNativeAuth()!.currentUser?.updateProfile(profile);
    return;
  }

  await updateWebProfile(webAuth.currentUser!, profile);
};

export const signInWithGooglePopup = async () => {
  const provider = new GoogleAuthProvider();
  provider.setCustomParameters({ prompt: 'select_account' });
  return signInWithPopup(webAuth, provider);
};

export const signInWithApplePopup = async () => {
  const provider = new OAuthProvider('apple.com');
  provider.addScope('email');
  provider.addScope('name');
  return signInWithPopup(webAuth, provider);
};

export const createGoogleCredential = (idToken: string) => {
  if (isNativeAuthRuntime) {
    return getNativeAuthModule()!.GoogleAuthProvider.credential(idToken);
  }

  return GoogleAuthProvider.credential(idToken);
};

export const createAppleCredential = (idToken: string, rawNonce: string) => {
  if (isNativeAuthRuntime) {
    return getNativeAuthModule()!.AppleAuthProvider.credential(idToken, rawNonce);
  }

  return new OAuthProvider('apple.com').credential({ idToken, rawNonce });
};

export const signInWithProviderCredential = async (credential: any): Promise<AppUserCredential> => {
  if (isNativeAuthRuntime) {
    return normalizeUserCredential(await getNativeAuth()!.signInWithCredential(credential));
  }

  return normalizeUserCredential(await signInWithWebCredential(webAuth, credential));
};

export const startPhoneNumberSignIn = async (phoneNumber: string, verifier?: RecaptchaVerifier): Promise<ConfirmationResult> => {
  if (isNativeAuthRuntime) {
    return normalizeConfirmationResult(await getNativeAuth()!.signInWithPhoneNumber(phoneNumber));
  }

  if (!verifier) {
    throw new Error('A reCAPTCHA verifier is required for web phone authentication.');
  }

  return normalizeConfirmationResult(await signInWithWebPhoneNumber(webAuth, phoneNumber, verifier));
};

export {
  addDoc,
  collection,
  deleteDoc,
  doc,
  getDoc,
  limit,
  onSnapshot,
  orderBy,
  query,
  RecaptchaVerifier,
  setDoc,
  setPersistence,
  signInWithPopup,
  Timestamp,
  updateDoc,
};
