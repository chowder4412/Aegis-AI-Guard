import { Linking, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { ArrowLeft, ExternalLink, Mail, ShieldCheck } from 'lucide-react-native';
import { fonts, palette, shadows, spacing } from '../theme';

type PublicInfoVariant = 'privacy' | 'terms' | 'support';

interface PublicInfoPageProps {
  variant: PublicInfoVariant;
  onBack?: () => void;
}

const SUPPORT_EMAIL = 'mustealawal@gmail.com';
const APP_DOMAIN = 'https://aegis-ai-guard.web.app';

const openExternal = async (url: string) => {
  try {
    await Linking.openURL(url);
  } catch {
    // Ignore open failures on unsupported surfaces.
  }
};

const pageContent: Record<
  PublicInfoVariant,
  {
    eyebrow: string;
    title: string;
    intro: string;
    sections: Array<{ heading: string; body: string[] }>;
  }
> = {
  privacy: {
    eyebrow: 'Privacy Policy',
    title: 'How Aegis AI Guard uses and protects your data',
    intro:
      'Aegis AI Guard is a phishing and mailbox-protection application that analyzes suspicious emails, links, and linked Gmail inbox activity to help users detect fraud, phishing, spoofing, and malware-related threats.',
    sections: [
      {
        heading: 'What data we collect',
        body: [
          'We collect account identity details needed to operate the product, including your email address, display name, and authentication identifiers from Firebase Authentication.',
          'When you link a Gmail mailbox, we store mailbox metadata, OAuth tokens, sync timestamps, message-derived threat findings, and security logs needed to run mailbox scanning and protection features.',
          'When you manually scan an email or URL, we store the scan input preview, detection result, confidence, recommendations, and threat records in Firestore for your workspace history.',
        ],
      },
      {
        heading: 'How we use Google user data',
        body: [
          'If you connect Gmail, Aegis AI Guard requests Gmail read-only access only to inspect inbox messages for phishing indicators, malicious links, suspicious credential forms, and related mailbox threats.',
          'Google user data is used only to provide mailbox synchronization, threat analysis, and user-visible security alerts. We do not use Gmail data for advertising, resale, or unrelated profiling.',
          'Google user data is not transferred to third parties except subprocessors or cloud infrastructure strictly required to deliver the security analysis service.',
        ],
      },
      {
        heading: 'How we protect your data',
        body: [
          'Authentication is handled through Firebase Authentication, user-scoped data is stored in Firestore, and mailbox access is limited to the authenticated user workspace.',
          'Sensitive mailbox operations are performed through backend APIs and sandboxed analysis services designed to isolate risky content and suspicious links away from the end-user device when possible.',
          'We retain security logs and scan records only as long as needed to provide the application, maintain audit history, and improve your threat visibility inside the product.',
        ],
      },
      {
        heading: 'Your choices',
        body: [
          'You can unlink a Gmail mailbox from the application, revoke Google access from your Google account settings, or request support regarding your stored data.',
          'You can also stop using the service at any time by signing out and discontinuing mailbox linking and scans.',
        ],
      },
      {
        heading: 'Contact',
        body: [
          `For privacy questions or deletion/support requests, contact ${SUPPORT_EMAIL}.`,
        ],
      },
    ],
  },
  terms: {
    eyebrow: 'Terms of Service',
    title: 'Terms for using Aegis AI Guard',
    intro:
      'These terms govern your use of Aegis AI Guard, including phishing detection, Gmail mailbox analysis, manual scans, and related security workflows provided through the app and supporting backend services.',
    sections: [
      {
        heading: 'Use of the service',
        body: [
          'You may use the service only for lawful security analysis, personal protection, research, or internal organizational review.',
          'You must not use the service to access data you are not authorized to inspect, to bypass legal restrictions, or to perform abusive or harmful security testing against third-party systems.',
        ],
      },
      {
        heading: 'Google account and mailbox access',
        body: [
          'When you link Gmail, you authorize Aegis AI Guard to read mailbox content strictly for security detection and mailbox threat monitoring features.',
          'You remain responsible for reviewing any alerts, deciding how to handle flagged messages, and revoking access if you no longer want the service connected to your mailbox.',
        ],
      },
      {
        heading: 'Security analysis limitations',
        body: [
          'Aegis AI Guard provides detection support and security recommendations, but no automated system can guarantee perfect detection or complete prevention of all phishing, fraud, or malware threats.',
          'You should continue to exercise caution when interacting with email, credentials, attachments, and links, even when the service reports low risk.',
        ],
      },
      {
        heading: 'Availability and changes',
        body: [
          'We may update, improve, suspend, or discontinue parts of the service as the product evolves, including backend models, rules, and mailbox-analysis logic.',
          'We may also revise these terms as needed to reflect changes in the product or legal requirements.',
        ],
      },
      {
        heading: 'Contact',
        body: [
          `Questions about these terms can be sent to ${SUPPORT_EMAIL}.`,
        ],
      },
    ],
  },
  support: {
    eyebrow: 'Support',
    title: 'Support and contact information',
    intro:
      'Use this page for app support, OAuth verification references, privacy requests, and questions about Gmail mailbox access in Aegis AI Guard.',
    sections: [
      {
        heading: 'Support contact',
        body: [
          `Primary support email: ${SUPPORT_EMAIL}`,
          `Application domain: ${APP_DOMAIN}`,
        ],
      },
      {
        heading: 'What to include in a support request',
        body: [
          'Describe whether the issue affects sign-in, Gmail linking, manual scanning, threat alerts, or mailbox synchronization.',
          'Include the email address used for testing, the approximate time of the issue, your platform (web, Android, or iOS), and screenshots if available.',
        ],
      },
      {
        heading: 'Verification-related help',
        body: [
          'If Google shows an unverified-app warning during Gmail linking, the app may still be in testing mode or pending OAuth verification for sensitive Gmail scopes.',
          'During testing, only approved test users should attempt the Gmail-linking flow until Google verification is completed.',
        ],
      },
    ],
  },
};

export const PublicInfoPage = ({ variant, onBack }: PublicInfoPageProps) => {
  const content = pageContent[variant];

  return (
    <ScrollView contentContainerStyle={styles.scrollContent} style={styles.scrollView}>
      <View style={styles.container}>
        <View style={styles.headerCard}>
          <View style={styles.headerTopRow}>
            {onBack ? (
              <Pressable onPress={onBack} style={({ pressed }) => [styles.backButton, pressed && styles.pressed]}>
                <ArrowLeft color={palette.primary} size={16} />
                <Text style={styles.backButtonText}>Back to App</Text>
              </Pressable>
            ) : <View />}
            <View style={styles.badge}>
              <ShieldCheck color={palette.secondary} size={16} />
              <Text style={styles.badgeText}>{content.eyebrow}</Text>
            </View>
          </View>

          <Text style={styles.title}>{content.title}</Text>
          <Text style={styles.intro}>{content.intro}</Text>

          <View style={styles.linkRow}>
            <Pressable onPress={() => void openExternal(`mailto:${SUPPORT_EMAIL}`)} style={({ pressed }) => [styles.linkButton, pressed && styles.pressed]}>
              <Mail color={palette.onSecondary} size={16} />
              <Text style={styles.linkButtonText}>Contact Support</Text>
            </Pressable>
            <Pressable onPress={() => void openExternal(APP_DOMAIN)} style={({ pressed }) => [styles.secondaryButton, pressed && styles.pressed]}>
              <ExternalLink color={palette.primary} size={16} />
              <Text style={styles.secondaryButtonText}>Open App</Text>
            </Pressable>
          </View>
        </View>

        {content.sections.map((section) => (
          <View key={section.heading} style={styles.sectionCard}>
            <Text style={styles.sectionHeading}>{section.heading}</Text>
            {section.body.map((paragraph) => (
              <Text key={paragraph} style={styles.sectionBody}>
                {paragraph}
              </Text>
            ))}
          </View>
        ))}
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    paddingHorizontal: spacing.screen,
    paddingVertical: 28,
    alignItems: 'center',
  },
  container: {
    width: '100%',
    maxWidth: 1040,
    gap: 18,
  },
  headerCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 30,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
    padding: 28,
    gap: 16,
    ...shadows.card,
  },
  headerTopRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
    flexWrap: 'wrap',
  },
  backButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderRadius: 999,
    backgroundColor: palette.surfaceHighest,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
  },
  backButtonText: {
    color: palette.primary,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  badge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
    borderRadius: 999,
    backgroundColor: 'rgba(74,225,131,0.1)',
  },
  badgeText: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 11,
    letterSpacing: 1.5,
    textTransform: 'uppercase',
  },
  title: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 34,
    lineHeight: 38,
  },
  intro: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 15,
    lineHeight: 24,
    maxWidth: 800,
  },
  linkRow: {
    flexDirection: 'row',
    gap: 12,
    flexWrap: 'wrap',
  },
  linkButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 16,
    paddingVertical: 13,
    borderRadius: 18,
    backgroundColor: palette.secondary,
  },
  linkButtonText: {
    color: palette.onSecondary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  secondaryButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 16,
    paddingVertical: 13,
    borderRadius: 18,
    backgroundColor: palette.surfaceHighest,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.35)',
  },
  secondaryButtonText: {
    color: palette.primary,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  sectionCard: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 24,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.28)',
    padding: 24,
    gap: 12,
  },
  sectionHeading: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 22,
  },
  sectionBody: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 23,
  },
  pressed: {
    opacity: 0.92,
  },
});
