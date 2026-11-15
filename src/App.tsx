import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Platform, ScrollView, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { LinearGradient } from 'expo-linear-gradient';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import * as SplashScreen from 'expo-splash-screen';
import { useFonts, Inter_400Regular, Inter_500Medium, Inter_600SemiBold } from '@expo-google-fonts/inter';
import { Manrope_700Bold, Manrope_800ExtraBold } from '@expo-google-fonts/manrope';

import { TopAppBar } from './components/TopAppBar';
import { BottomNavBar, type AppTab } from './components/BottomNavBar';
import { AuthScreen } from './components/AuthScreen';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { Education } from './pages/Education';
import { Logs } from './pages/Logs';
import { Settings } from './pages/Settings';
import { PublicInfoPage } from './pages/PublicInfoPage';
import { AcademyProvider } from './context/AcademyContext';
import { LinkedEmailsProvider } from './context/LinkedEmailsContext';
import { AuthProvider, useAuth } from './context/AuthContext';
import { fonts, palette, spacing } from './theme';

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
  const { user, loading } = useAuth();

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
        return <Dashboard onNavigateTab={setActiveTab} />;
    }
  }, [activeTab]);

  if (loading) {
    return (
      <View style={styles.centeredScreen}>
        <ActivityIndicator color={palette.secondary} size="large" />
        <Text style={styles.loadingText}>Initializing Aegis Security...</Text>
      </View>
    );
  }

  if (!user) {
    return <AuthScreen />;
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
          <AcademyProvider>
            <LinkedEmailsProvider>
              <AppContent />
            </LinkedEmailsProvider>
          </AcademyProvider>
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
  loadingText: {
    marginTop: 16,
    color: palette.onSurfaceMuted,
    fontFamily: fonts.headline,
    fontSize: 12,
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
