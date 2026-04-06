import { Pressable, StyleSheet, Text, View } from 'react-native';
import { FileText, GraduationCap, LayoutDashboard, SearchCode, Settings as SettingsIcon } from 'lucide-react-native';
import { useResponsive } from '../hooks/useResponsive';
import { fonts, palette, radii, shadows } from '../theme';

export type AppTab = 'dashboard' | 'scanner' | 'education' | 'logs' | 'settings';

interface BottomNavBarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
}

const tabs = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'scanner', label: 'Scanner', icon: SearchCode },
  { id: 'education', label: 'Education', icon: GraduationCap },
  { id: 'logs', label: 'Logs', icon: FileText },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
] as const;

export const BottomNavBar = ({ activeTab, setActiveTab }: BottomNavBarProps) => {
  const { width, isDesktop, isTablet } = useResponsive();
  const isCompactMobile = !isTablet;
  const navWidth = Math.min(width - 24, isDesktop ? 1180 : width - 24);

  return (
    <View style={[styles.wrapper, { width: navWidth, left: (width - navWidth) / 2 }, isDesktop && styles.wrapperDesktop]}>
      {tabs.map((tab) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;

        return (
          <Pressable
            key={tab.id}
            onPress={() => setActiveTab(tab.id)}
            style={({ pressed }) => [
              styles.tab,
              isCompactMobile && styles.tabCompactMobile,
              isActive && styles.activeTab,
              isCompactMobile && isActive && styles.activeTabCompactMobile,
              pressed && styles.pressed,
            ]}
          >
            <Icon color={isActive ? palette.secondary : palette.primaryMuted} size={20} strokeWidth={isActive ? 2.5 : 2} />
            {!isCompactMobile || isActive ? (
              <Text style={[styles.tabText, isCompactMobile && styles.tabTextCompactMobile, isActive && styles.activeTabText]}>
                {tab.label}
              </Text>
            ) : null}
            {isActive ? <View style={styles.activeDot} /> : null}
          </Pressable>
        );
      })}
    </View>
  );
};

const styles = StyleSheet.create({
  wrapper: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 10,
    paddingVertical: 12,
    marginBottom: 18,
    borderRadius: 28,
    backgroundColor: 'rgba(16,19,26,0.96)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.45)',
    ...shadows.card,
  },
  wrapperDesktop: {
    paddingHorizontal: 14,
    paddingVertical: 10,
  },
  tab: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 10,
    borderRadius: radii.button,
    gap: 6,
  },
  tabCompactMobile: {
    paddingVertical: 12,
    gap: 4,
  },
  activeTab: {
    backgroundColor: palette.surfaceHighest,
  },
  activeTabCompactMobile: {
    flex: 1.35,
  },
  pressed: {
    opacity: 0.9,
  },
  tabText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 1,
    textTransform: 'uppercase',
  },
  tabTextCompactMobile: {
    fontSize: 9,
    letterSpacing: 0.6,
  },
  activeTabText: {
    color: palette.secondary,
  },
  activeDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
    backgroundColor: palette.secondary,
  },
});
