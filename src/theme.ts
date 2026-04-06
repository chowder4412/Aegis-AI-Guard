import { Platform } from 'react-native';

export const palette = {
  background: '#10131A',
  backgroundDeep: '#0B0E14',
  surface: '#10131A',
  surfaceLow: '#191C22',
  surfaceHigh: '#272A31',
  surfaceHighest: '#32353C',
  primary: '#BBC6E2',
  primaryMuted: '#78839C',
  secondary: '#4AE183',
  secondaryDark: '#06BB63',
  onSecondary: '#003919',
  onSurface: '#E1E2EB',
  onSurfaceMuted: '#C4C6CC',
  outline: '#44474C',
  error: '#FFB4AB',
  errorStrong: '#FF5C52',
  warning: '#F4A43A',
  success: '#27C67A',
  info: '#4F7BFF',
} as const;

export const fonts = {
  headlineBold: 'Manrope_800ExtraBold',
  headline: 'Manrope_700Bold',
  body: 'Inter_400Regular',
  bodyMedium: 'Inter_500Medium',
  bodySemiBold: 'Inter_600SemiBold',
} as const;

export const spacing = {
  screen: 24,
  card: 24,
  largeCard: 28,
  topBarHeight: 88,
  bottomNavHeight: 108,
} as const;

export const radii = {
  pill: 999,
  card: 24,
  cardLarge: 32,
  button: 18,
} as const;

const makeShadow = (opacity: number, radius: number, y: number, elevation: number) =>
  Platform.select({
    web: {
      boxShadow: `0px ${y}px ${radius}px rgba(0, 0, 0, ${opacity})`,
    },
    default: {
      shadowColor: '#000000',
      shadowOpacity: opacity,
      shadowRadius: radius,
      shadowOffset: { width: 0, height: y },
      elevation,
    },
  });

export const shadows = {
  card: makeShadow(0.24, 22, 12, 8),
  subtle: makeShadow(0.16, 14, 6, 5),
} as const;

export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';
export type ThreatCategory = 'Phishing' | 'Malware' | 'Spoofing' | 'Social' | 'Other';

export const riskColors: Record<RiskLevel, { tint: string; text: string; fill: string }> = {
  Critical: { tint: 'rgba(255,92,82,0.16)', text: palette.error, fill: palette.errorStrong },
  High: { tint: 'rgba(244,164,58,0.16)', text: '#FFB463', fill: palette.warning },
  Medium: { tint: 'rgba(187,198,226,0.14)', text: palette.primary, fill: palette.primaryMuted },
  Low: { tint: 'rgba(74,225,131,0.14)', text: palette.secondary, fill: palette.success },
};

export const categoryColors: Record<ThreatCategory, { tint: string; text: string }> = {
  Phishing: { tint: 'rgba(74,225,131,0.14)', text: palette.secondary },
  Malware: { tint: 'rgba(244,164,58,0.16)', text: palette.warning },
  Spoofing: { tint: 'rgba(79,123,255,0.16)', text: palette.info },
  Social: { tint: 'rgba(255,92,82,0.16)', text: palette.error },
  Other: { tint: 'rgba(187,198,226,0.14)', text: palette.primary },
};

export const formatRelativeTime = (timestamp: string) => {
  const now = Date.now();
  const then = new Date(timestamp).getTime();
  const diffMinutes = Math.max(0, Math.round((now - then) / 60000));

  if (diffMinutes < 1) {
    return 'Just now';
  }
  if (diffMinutes < 60) {
    return `${diffMinutes}m ago`;
  }
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours}h ago`;
  }
  return new Date(timestamp).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
};
