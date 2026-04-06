import { Alert, Image, Pressable, StyleSheet, Text, View } from 'react-native';
import { LogOut } from 'lucide-react-native';
import { useAuth } from '../context/AuthContext';
import { useResponsive } from '../hooks/useResponsive';
import { fonts, palette, radii, shadows, spacing } from '../theme';

export const TopAppBar = () => {
  const { user, logout } = useAuth();
  const { isTablet } = useResponsive();

  const performLogout = () => {
    void logout();
  };

  const handleLogout = () => {
    if (typeof window !== 'undefined' && typeof window.confirm === 'function') {
      if (window.confirm('End your secure session on this device?')) {
        performLogout();
      }
      return;
    }

    Alert.alert('Sign out', 'End your secure session on this device?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Sign Out', style: 'destructive', onPress: performLogout },
    ]);
  };

  return (
    <View style={styles.container}>
      <View style={styles.leftGroup}>
        <View style={styles.avatarWrap}>
          {user?.photoURL ? (
            <Image source={{ uri: user.photoURL }} style={styles.avatar} />
          ) : (
            <View style={styles.avatarFallback}>
              <Text style={styles.avatarFallbackText}>A</Text>
            </View>
          )}
        </View>
        <View>
          <Text style={styles.title}>Sentient Security</Text>
          <Text style={styles.subtitle}>{user?.displayName || 'Aegis Analyst'}</Text>
        </View>
      </View>

      <View style={styles.rightGroup}>
        <View style={styles.statusChip}>
          <View style={styles.statusDot} />
          {isTablet ? <Text style={styles.statusText}>Aegis Active Guard</Text> : null}
        </View>

        <Pressable hitSlop={10} onPress={handleLogout} style={({ pressed }) => [styles.actionButton, pressed && styles.pressed]}>
          <LogOut color={palette.primary} size={isTablet ? 20 : 22} />
        </Pressable>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    zIndex: 20,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: spacing.screen,
    paddingTop: 10,
    paddingBottom: 16,
    backgroundColor: 'rgba(16,19,26,0.92)',
  },
  leftGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  rightGroup: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  avatarWrap: {
    width: 42,
    height: 42,
    borderRadius: 21,
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.5)',
    backgroundColor: palette.surfaceHigh,
  },
  avatar: {
    width: '100%',
    height: '100%',
  },
  avatarFallback: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
  },
  avatarFallbackText: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 18,
  },
  title: {
    color: palette.primary,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  subtitle: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    marginTop: 2,
  },
  statusChip: {
    borderRadius: 999,
    backgroundColor: 'rgba(25,28,34,0.94)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.45)',
    paddingHorizontal: 14,
    paddingVertical: 10,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    ...shadows.subtle,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    backgroundColor: palette.secondary,
  },
  statusText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1.7,
    textTransform: 'uppercase',
  },
  actionButton: {
    width: 42,
    height: 42,
    borderRadius: radii.button,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: palette.surfaceHigh,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.45)',
    ...shadows.subtle,
  },
  pressed: {
    opacity: 0.9,
    transform: [{ scale: 0.97 }],
  },
});
