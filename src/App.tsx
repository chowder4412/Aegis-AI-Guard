import { useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, Alert, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import * as AppleAuthentication from 'expo-apple-authentication';
import * as ExpoLinking from 'expo-linking';
import * as Crypto from 'expo-crypto';
import { StatusBar } from 'expo-status-bar';
import { LinearGradient } from 'expo-linear-gradient';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import * as SplashScreen from 'expo-splash-screen';
import * as Google from 'expo-auth-session/providers/google';
import { useFonts, Inter_400Regular, Inter_500Medium, Inter_600SemiBold } from '@expo-google-fonts/inter';
import { Manrope_700Bold, Manrope_800ExtraBold } from '@expo-google-fonts/manrope';
import { Apple, Chrome, Mail, ShieldAlert, Smartphone } from 'lucide-react-native';
import { TopAppBar } from './components/TopAppBar';
import { BottomNavBar, type AppTab } from './components/BottomNavBar';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { Education } from './pages/Education';
import { Logs } from './pages/Logs';
import { Settings } from './pages/Settings';
import { PublicInfoPage } from './pages/PublicInfoPage';
import { LinkedEmailsProvider } from './context/LinkedEmailsContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import {
  auth,
  type ConfirmationResult,
  createAppleCredential,
  getCurrentAuthUser,
  isNativeAuthRuntime,
  RecaptchaVerifier,
  signInWithProviderCredential,
  startPhoneNumberSignIn,
  updateCurrentUserProfile,
} from './firebase';
import { GOOGLE_ANDROID_CLIENT_ID, GOOGLE_IOS_CLIENT_ID, GOOGLE_WEB_CLIENT_ID } from './services/googleAuthService';
import { fonts, palette, radii, shadows, spacing } from './theme';

void SplashScreen.preventAutoHideAsync();

type PublicRoute = 'app' | 'privacy' | 'terms' | 'support';

const getPublicRoute = (): PublicRoute => {
  if (Platform.OS !== 'web' || typeof window === 'undefined') {
    return 'app';
  }

  const normalizedPath = window.location.pathname.replace(/\/+$/, '') || '/';
  if (normalizedPath === '/privacy') {
    return 'privacy';
  }
  if (normalizedPath === '/terms') {
    return 'terms';
  }
  if (normalizedPath === '/support') {
    return 'support';
  }

  return 'app';
};

const AppContent = () => {
  const [publicRoute, setPublicRoute] = useState<PublicRoute>(getPublicRoute);
  const [activeTab, setActiveTab] = useState<AppTab>('dashboard');
  const [authMode, setAuthMode] = useState<'signIn' | 'register'>('signIn');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const { user, loading, login, loginWithApple, loginWithGoogle, loginWithGoogleIdToken, register } = useAuth();
  const [googleSubmitting, setGoogleSubmitting] = useState(false);
  const [appleSubmitting, setAppleSubmitting] = useState(false);
  const [phoneSubmitting, setPhoneSubmitting] = useState(false);
  const [phoneStep, setPhoneStep] = useState<'idle' | 'codeSent'>('idle');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [phoneCode, setPhoneCode] = useState('');
  const [phoneHint, setPhoneHint] = useState('');
  const phoneConfirmationRef = useRef<ConfirmationResult | null>(null);
  const recaptchaVerifierRef = useRef<RecaptchaVerifier | null>(null);
  const appleSupported = Platform.OS === 'web' || Platform.OS === 'ios';
  const phoneSupported = Platform.OS === 'web' || isNativeAuthRuntime;
  const [googleRequest, googleResponse, promptGoogleAsync] = Google.useIdTokenAuthRequest({
    clientId: GOOGLE_WEB_CLIENT_ID,
    iosClientId: GOOGLE_IOS_CLIENT_ID,
    androidClientId: GOOGLE_ANDROID_CLIENT_ID,
    webClientId: GOOGLE_WEB_CLIENT_ID,
    scopes: ['openid', 'profile', 'email'],
    selectAccount: true,
  });

  useEffect(() => {
    if (Platform.OS !== 'web' || typeof window === 'undefined') {
      return;
    }

    const handleRouteChange = () => {
      setPublicRoute(getPublicRoute());
    };

    window.addEventListener('popstate', handleRouteChange);
    return () => {
      window.removeEventListener('popstate', handleRouteChange);
    };
  }, []);

  const navigateToApp = () => {
    if (Platform.OS === 'web' && typeof window !== 'undefined') {
      window.history.pushState({}, '', '/');
      setPublicRoute('app');
    }
  };

  if (publicRoute !== 'app') {
    return <PublicInfoPage variant={publicRoute} onBack={navigateToApp} />;
  }

  const content = useMemo(() => {
    switch (activeTab) {
      case 'scanner':
        return <Scanner />;
      case 'education':
        return <Education onNavigateTab={setActiveTab} />;
      case 'logs':
        return <Logs />;
      case 'settings':
        return <Settings onBack={() => setActiveTab('dashboard')} onNavigateTab={setActiveTab} />;
      case 'dashboard':
      default:
        return <Dashboard />;
    }
  }, [activeTab]);

  const handleAuthenticate = async () => {
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !password.trim() || (authMode === 'register' && !displayName.trim())) {
      Alert.alert('Missing fields', 'Enter the required account details before continuing.');
      return;
    }

    setIsSubmitting(true);
    try {
      if (authMode === 'register') {
        await register(displayName, normalizedEmail, password);
      } else {
        await login(normalizedEmail, password);
      }
      setPassword('');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Authentication failed.';
      Alert.alert('Authentication failed', message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getPhoneButtonLabel = () => (authMode === 'register' ? 'Create with Phone' : 'Continue with Phone');
  const getGoogleButtonLabel = () => (authMode === 'register' ? 'Create with Google' : 'Continue with Google');
  const getAppleButtonLabel = () => (authMode === 'register' ? 'Create with Apple' : 'Continue with Apple');
  const getPhoneSupportCopy = () =>
    phoneSupported
      ? isNativeAuthRuntime
        ? 'Use native phone verification for SMS-based account access in the development build.'
        : 'Use phone verification for SMS-based account access.'
      : 'Phone auth is available on the web build today. For native iOS/Android, use the development-build path with the new React Native Firebase integration.';

  const resetPhoneAuthState = () => {
    setPhoneStep('idle');
    setPhoneCode('');
    setPhoneHint('');
    phoneConfirmationRef.current = null;
  };

  const ensureRecaptchaVerifier = () => {
    if (Platform.OS !== 'web' || typeof window === 'undefined') {
      throw new Error('Phone authentication is currently available on the web build.');
    }

    const containerId = 'aegis-phone-recaptcha';
    if (!document.getElementById(containerId)) {
      throw new Error('Phone authentication is still initializing. Please try again.');
    }

    if (recaptchaVerifierRef.current) {
      return recaptchaVerifierRef.current;
    }

    const verifier = new RecaptchaVerifier(auth, containerId, {
      size: 'invisible',
    });
    recaptchaVerifierRef.current = verifier;
    return verifier;
  };

  useEffect(() => {
    const handleGoogleResponse = async () => {
      if (!googleResponse) {
        return;
      }

      if (googleResponse.type !== 'success') {
        if (googleResponse.type === 'error') {
          Alert.alert('Google sign-in failed', 'Google could not complete authentication.');
        }
        setGoogleSubmitting(false);
        return;
      }

      const idToken = googleResponse.params.id_token;
      if (!idToken) {
        Alert.alert('Google sign-in failed', 'Google did not return an ID token for Firebase authentication.');
        setGoogleSubmitting(false);
        return;
      }

      try {
        await loginWithGoogleIdToken(idToken);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Google sign-in failed.';
        Alert.alert('Google sign-in failed', message);
      } finally {
        setGoogleSubmitting(false);
      }
    };

    void handleGoogleResponse();
  }, [googleResponse, loginWithGoogleIdToken]);

  const handleGoogleLogin = async () => {
    setGoogleSubmitting(true);
    try {
      if (Platform.OS === 'web') {
        await loginWithGoogle();
        return;
      }

      if (!googleRequest) {
        Alert.alert('Google sign-in unavailable', 'The Google auth request is not ready yet.');
        return;
      }

      await promptGoogleAsync({
        showInRecents: true,
      });
    } catch (error) {
      setGoogleSubmitting(false);
      const message = error instanceof Error ? error.message : 'Unable to start Google sign-in.';
      Alert.alert('Google sign-in failed', message);
    }
  };

  const handleAppleLogin = async () => {
    setAppleSubmitting(true);
    try {
      if (Platform.OS === 'ios') {
        const available = await AppleAuthentication.isAvailableAsync();
        if (!available) {
          throw new Error('Apple sign-in is unavailable on this iOS device.');
        }

        const rawNonce = Crypto.randomUUID();
        const hashedNonce = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, rawNonce);
        const credential = await AppleAuthentication.signInAsync({
          requestedScopes: [AppleAuthentication.AppleAuthenticationScope.FULL_NAME, AppleAuthentication.AppleAuthenticationScope.EMAIL],
          nonce: hashedNonce,
        });

        if (!credential.identityToken) {
          throw new Error('Apple did not return an identity token.');
        }

        const firebaseCredential = createAppleCredential(credential.identityToken, rawNonce);
        await signInWithProviderCredential(firebaseCredential);

        const fullName = [credential.fullName?.givenName, credential.fullName?.familyName].filter(Boolean).join(' ').trim();
        if (fullName && !getCurrentAuthUser()?.displayName) {
          await updateCurrentUserProfile({ displayName: fullName });
        }
        return;
      }

      await loginWithApple();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to start Apple sign-in.';
      Alert.alert('Apple sign-in failed', message);
    } finally {
      setAppleSubmitting(false);
    }
  };

  const handlePhoneCodeRequest = async () => {
    const normalizedPhone = phoneNumber.trim();
    if (!normalizedPhone) {
      Alert.alert('Phone number required', 'Enter a full phone number in international format, for example +2348012345678.');
      return;
    }

    setPhoneSubmitting(true);
    try {
      const verifier = isNativeAuthRuntime ? undefined : ensureRecaptchaVerifier();
      const confirmation = await startPhoneNumberSignIn(normalizedPhone, verifier);
      phoneConfirmationRef.current = confirmation;
      setPhoneStep('codeSent');
      setPhoneHint(`A verification code was sent to ${normalizedPhone}.`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to send the verification code.';
      Alert.alert('Phone sign-in failed', message);
      recaptchaVerifierRef.current?.clear();
      recaptchaVerifierRef.current = null;
    } finally {
      setPhoneSubmitting(false);
    }
  };

  const handlePhoneCodeConfirm = async () => {
    if (!phoneConfirmationRef.current) {
      Alert.alert('Verification not started', 'Request a verification code first.');
      return;
    }

    const normalizedCode = phoneCode.trim();
    if (!normalizedCode) {
      Alert.alert('Code required', 'Enter the SMS verification code before continuing.');
      return;
    }

    setPhoneSubmitting(true);
    try {
      await phoneConfirmationRef.current.confirm(normalizedCode);
      resetPhoneAuthState();
      setPhoneNumber('');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to confirm the verification code.';
      Alert.alert('Phone verification failed', message);
    } finally {
      setPhoneSubmitting(false);
    }
  };

  if (loading) {
    return (
      <View style={styles.centeredScreen}>
        <ActivityIndicator color={palette.secondary} size="large" />
        <Text style={styles.loadingText}>Initializing Aegis Security...</Text>
      </View>
    );
  }

  if (!user) {
    return (
      <ScrollView
        contentContainerStyle={styles.authScrollContent}
        keyboardShouldPersistTaps="handled"
        showsVerticalScrollIndicator={false}
        style={styles.authScrollView}
      >
        <View style={styles.loginCard}>
          <View style={styles.loginIconWrap}>
            <View style={styles.loginGlow} />
            <ShieldAlert color={palette.secondary} size={48} />
          </View>
          <Text style={styles.loginTitle}>Aegis AI Guard</Text>
          <Text style={styles.loginBody}>
            Use a real Firebase account session so scans, inbox links, and threat history stay tied to your workspace.
          </Text>

          <View style={styles.authModeRow}>
            <Pressable
              onPress={() => setAuthMode('signIn')}
              style={({ pressed }) => [styles.authModeButton, authMode === 'signIn' && styles.authModeButtonActive, pressed && styles.buttonPressed]}
            >
              <Text style={[styles.authModeText, authMode === 'signIn' && styles.authModeTextActive]}>Sign In</Text>
            </Pressable>
            <Pressable
              onPress={() => setAuthMode('register')}
              style={({ pressed }) => [styles.authModeButton, authMode === 'register' && styles.authModeButtonActive, pressed && styles.buttonPressed]}
            >
              <Text style={[styles.authModeText, authMode === 'register' && styles.authModeTextActive]}>Create Account</Text>
            </Pressable>
          </View>

          {authMode === 'register' ? (
            <TextInput
              autoCapitalize="words"
              onChangeText={setDisplayName}
              placeholder="Display name"
              placeholderTextColor="rgba(196,198,204,0.42)"
              style={styles.authInput}
              value={displayName}
            />
          ) : null}

          <TextInput
            autoCapitalize="none"
            keyboardType="email-address"
            onChangeText={setEmail}
            placeholder="Work email"
            placeholderTextColor="rgba(196,198,204,0.42)"
            style={styles.authInput}
            value={email}
          />
          <TextInput
            autoCapitalize="none"
            onChangeText={setPassword}
            placeholder="Password"
            placeholderTextColor="rgba(196,198,204,0.42)"
            secureTextEntry
            style={styles.authInput}
            value={password}
          />

          <Pressable
            disabled={isSubmitting}
            onPress={() => void handleAuthenticate()}
            style={({ pressed }) => [styles.primaryButton, (pressed || isSubmitting) && styles.buttonPressed]}
          >
            {isSubmitting ? <ActivityIndicator color={palette.onSecondary} size="small" /> : <Mail color={palette.onSecondary} size={18} />}
            <Text style={styles.primaryButtonText}>{authMode === 'register' ? 'Create Secure Account' : 'Sign In Securely'}</Text>
          </Pressable>

          <View style={styles.separatorRow}>
            <View style={styles.separatorLine} />
            <Text style={styles.separatorText}>or use identity provider</Text>
            <View style={styles.separatorLine} />
          </View>

          <View style={styles.socialStack}>
            <Pressable
              disabled={Platform.OS !== 'web' && !googleRequest ? true : googleSubmitting}
              onPress={() => void handleGoogleLogin()}
              style={({ pressed }) => [styles.socialButton, ((Platform.OS !== 'web' && !googleRequest) || googleSubmitting || pressed) && styles.buttonPressed]}
            >
              {googleSubmitting ? <ActivityIndicator color={palette.onSurface} size="small" /> : <Chrome color={palette.onSurface} size={18} />}
              <Text style={styles.googleButtonText}>{getGoogleButtonLabel()}</Text>
            </Pressable>

            <Pressable
              disabled={!appleSupported || appleSubmitting}
              onPress={() => void handleAppleLogin()}
              style={({ pressed }) => [styles.socialButton, (!appleSupported || appleSubmitting || pressed) && styles.buttonPressed, !appleSupported && styles.socialButtonDisabled]}
            >
              {appleSubmitting ? <ActivityIndicator color={palette.onSurface} size="small" /> : <Apple color={palette.onSurface} size={18} />}
              <Text style={styles.googleButtonText}>{getAppleButtonLabel()}</Text>
            </Pressable>
            {!appleSupported ? <Text style={styles.providerFootnote}>Apple sign-in is currently available on web and iOS.</Text> : null}

            <View style={styles.phoneAuthCard}>
              <View style={styles.phoneRow}>
                <Smartphone color={palette.onSurface} size={18} />
                <Text style={styles.phoneTitle}>{getPhoneButtonLabel()}</Text>
              </View>
              <Text style={styles.phoneHint}>{getPhoneSupportCopy()}</Text>
              <TextInput
                autoCapitalize="none"
                keyboardType="phone-pad"
                onChangeText={setPhoneNumber}
                placeholder="+2348012345678"
                placeholderTextColor="rgba(196,198,204,0.42)"
                style={[styles.authInput, !phoneSupported && styles.authInputDisabled]}
                value={phoneNumber}
                editable={phoneSupported}
              />
              {phoneStep === 'codeSent' ? (
                <TextInput
                  autoCapitalize="none"
                  keyboardType="number-pad"
                  onChangeText={setPhoneCode}
                  placeholder="SMS verification code"
                  placeholderTextColor="rgba(196,198,204,0.42)"
                  style={[styles.authInput, !phoneSupported && styles.authInputDisabled]}
                  value={phoneCode}
                  editable={phoneSupported}
                />
              ) : null}
              {phoneHint ? <Text style={styles.phoneStatus}>{phoneHint}</Text> : null}
              <View style={styles.phoneActions}>
                <Pressable
                  disabled={!phoneSupported || phoneSubmitting}
                  onPress={() => void handlePhoneCodeRequest()}
                  style={({ pressed }) => [styles.phoneButton, (!phoneSupported || phoneSubmitting || pressed) && styles.buttonPressed, !phoneSupported && styles.socialButtonDisabled]}
                >
                  {phoneSubmitting && phoneStep === 'idle' ? <ActivityIndicator color={palette.onSecondary} size="small" /> : <Text style={styles.phoneButtonText}>Send Code</Text>}
                </Pressable>
                {phoneStep === 'codeSent' ? (
                  <Pressable
                    disabled={!phoneSupported || phoneSubmitting}
                    onPress={() => void handlePhoneCodeConfirm()}
                    style={({ pressed }) => [styles.phoneButtonSecondary, (!phoneSupported || phoneSubmitting || pressed) && styles.buttonPressed, !phoneSupported && styles.socialButtonDisabled]}
                  >
                    {phoneSubmitting ? <ActivityIndicator color={palette.onSurface} size="small" /> : <Text style={styles.phoneButtonSecondaryText}>Verify Code</Text>}
                  </Pressable>
                ) : null}
              </View>
              {Platform.OS === 'web' ? <View nativeID="aegis-phone-recaptcha" style={styles.recaptchaMount} /> : null}
            </View>
          </View>
          {Platform.OS === 'android' ? (
            <Text style={styles.googleHint}>
              Google sign-in uses the Firebase Android app registration. Add your release SHA fingerprints before shipping an Android build.
            </Text>
          ) : null}
          <Text style={styles.loginFootnote}>Firebase Auth backed session</Text>
        </View>
      </ScrollView>
    );
  }

  return (
    <View style={styles.appShell}>
      <TopAppBar />
      <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false} style={styles.scrollView}>
        {content}
      </ScrollView>
      <BottomNavBar activeTab={activeTab} setActiveTab={setActiveTab} />
    </View>
  );
};

export default function App() {
  const [fontsLoaded, fontError] = useFonts({
    Inter_400Regular,
    Inter_500Medium,
    Inter_600SemiBold,
    Manrope_700Bold,
    Manrope_800ExtraBold,
  });

  useEffect(() => {
    if (fontsLoaded || fontError) {
      void SplashScreen.hideAsync();
    }
  }, [fontError, fontsLoaded]);

  if (!fontsLoaded && !fontError) {
    return null;
  }

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <LinearGradient colors={[palette.background, '#131821', palette.backgroundDeep]} style={StyleSheet.absoluteFill} />
      <SafeAreaView style={styles.safeArea} edges={['top', 'left', 'right']}>
        <AuthProvider>
          <LinkedEmailsProvider>
            <AppContent />
          </LinkedEmailsProvider>
        </AuthProvider>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: 'transparent',
  },
  appShell: {
    flex: 1,
  },
  centeredScreen: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.screen,
  },
  authScrollView: {
    flex: 1,
  },
  authScrollContent: {
    flexGrow: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: spacing.screen,
    paddingVertical: 28,
  },
  loadingText: {
    marginTop: 16,
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 12,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  loginCard: {
    width: '100%',
    maxWidth: 440,
    backgroundColor: palette.surfaceLow,
    borderColor: 'rgba(68,71,76,0.4)',
    borderWidth: 1,
    borderRadius: 40,
    padding: 32,
    alignItems: 'center',
    gap: 14,
    ...shadows.card,
  },
  loginIconWrap: {
    width: 96,
    height: 96,
    borderRadius: 40,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(74,225,131,0.1)',
    marginBottom: 14,
  },
  loginGlow: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: palette.secondary,
    opacity: 0.12,
    borderRadius: 40,
  },
  loginTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 32,
    textAlign: 'center',
  },
  loginBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
    textAlign: 'center',
    marginBottom: 8,
  },
  authModeRow: {
    width: '100%',
    flexDirection: 'row',
    borderRadius: 20,
    backgroundColor: palette.surfaceHighest,
    padding: 4,
    gap: 6,
  },
  authModeButton: {
    flex: 1,
    borderRadius: 16,
    paddingVertical: 12,
    alignItems: 'center',
  },
  authModeButtonActive: {
    backgroundColor: palette.secondary,
  },
  authModeText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 1.6,
    textTransform: 'uppercase',
  },
  authModeTextActive: {
    color: palette.onSecondary,
  },
  authInput: {
    width: '100%',
    borderRadius: 18,
    backgroundColor: 'rgba(50,53,60,0.3)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    paddingHorizontal: 16,
    paddingVertical: 15,
    color: palette.onSurface,
    fontFamily: fonts.body,
    fontSize: 15,
  },
  primaryButton: {
    width: '100%',
    borderRadius: radii.button,
    backgroundColor: palette.secondary,
    paddingHorizontal: 20,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
    marginTop: 8,
  },
  primaryButtonText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
  },
  separatorRow: {
    width: '100%',
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  separatorLine: {
    flex: 1,
    height: 1,
    backgroundColor: 'rgba(68,71,76,0.35)',
  },
  separatorText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  socialStack: {
    width: '100%',
    gap: 12,
  },
  socialButton: {
    width: '100%',
    borderRadius: radii.button,
    backgroundColor: palette.surfaceHighest,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    paddingHorizontal: 20,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 10,
  },
  googleButtonText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
  },
  socialButtonDisabled: {
    opacity: 0.45,
  },
  providerFootnote: {
    marginTop: -4,
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  phoneAuthCard: {
    width: '100%',
    borderRadius: 24,
    backgroundColor: 'rgba(50,53,60,0.28)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    padding: 16,
    gap: 12,
  },
  authInputDisabled: {
    opacity: 0.55,
  },
  phoneRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  phoneTitle: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 15,
  },
  googleHint: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
    textAlign: 'center',
  },
  phoneHint: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  phoneStatus: {
    color: palette.secondary,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  phoneActions: {
    flexDirection: 'row',
    gap: 10,
  },
  phoneButton: {
    flex: 1,
    borderRadius: radii.button,
    backgroundColor: palette.secondary,
    minHeight: 50,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
  phoneButtonText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  phoneButtonSecondary: {
    flex: 1,
    borderRadius: radii.button,
    backgroundColor: palette.surfaceHighest,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    minHeight: 50,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
  phoneButtonSecondaryText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  recaptchaMount: {
    width: 1,
    height: 1,
    opacity: 0,
  },
  buttonPressed: {
    opacity: 0.92,
    transform: [{ scale: 0.98 }],
  },
  loginFootnote: {
    marginTop: 4,
    color: palette.primaryMuted,
    opacity: 0.7,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingTop: spacing.topBarHeight + 12,
    paddingBottom: 40,
    paddingHorizontal: spacing.screen,
    gap: 24,
    alignItems: 'center',
  },
});
