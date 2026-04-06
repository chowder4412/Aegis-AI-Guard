import { useEffect, useMemo, useState } from 'react';
import { ActivityIndicator, Alert, Linking, Platform, Pressable, StyleSheet, Text, View } from 'react-native';
import * as Google from 'expo-auth-session/providers/google';
import { Bot, Lock, Mail, RefreshCw, Shield, Trash2 } from 'lucide-react-native';
import { useAuth } from '../context/AuthContext';
import { useLinkedEmails } from '../context/LinkedEmailsContext';
import { useResponsive } from '../hooks/useResponsive';
import { storeBackendGmailMailboxSession } from '../services/backendMailboxService';
import { GMAIL_SCOPES, saveGmailMailboxSession } from '../services/gmailSyncService';
import { GOOGLE_ANDROID_CLIENT_ID, GOOGLE_IOS_CLIENT_ID, GOOGLE_WEB_CLIENT_ID } from '../services/googleAuthService';
import { fonts, palette, shadows } from '../theme';

export const EmailLinker = () => {
  const { isTablet } = useResponsive();
  const isMobile = !isTablet;
  const { user } = useAuth();
  const { linkedEmails, completeOAuthLink, linkRealEmail, removeEmail, retryEmail, loading, oauthMessage, oauthStatus, clearOAuthMessage } =
    useLinkedEmails();
  const [status, setStatus] = useState<'idle' | 'linking' | 'error'>('idle');
  const oauthLinkedEmails = useMemo(() => linkedEmails.filter((item) => item.provider === 'gmail-oauth'), [linkedEmails]);
  const [gmailRequest, gmailResponse, promptGmailAsync] = Google.useAuthRequest({
    clientId: GOOGLE_WEB_CLIENT_ID,
    iosClientId: GOOGLE_IOS_CLIENT_ID,
    androidClientId: GOOGLE_ANDROID_CLIENT_ID,
    webClientId: GOOGLE_WEB_CLIENT_ID,
    scopes: GMAIL_SCOPES,
    selectAccount: true,
    shouldAutoExchangeCode: true,
    extraParams:
      Platform.OS === 'web'
        ? undefined
        : {
            access_type: 'offline',
            prompt: 'consent',
          },
  });

  useEffect(() => {
    if (!oauthMessage) {
      return;
    }

    const timer = setTimeout(() => {
      clearOAuthMessage();
    }, 4000);

    return () => clearTimeout(timer);
  }, [clearOAuthMessage, oauthMessage]);

  useEffect(() => {
    const completeNativeGmailLink = async () => {
      if (!gmailResponse || !user) {
        return;
      }

      if (gmailResponse.type !== 'success') {
        if (gmailResponse.type === 'error') {
          setStatus('error');
          Alert.alert('Gmail connection failed', 'Google could not complete mailbox authorization.');
        } else {
          setStatus('idle');
        }
        return;
      }

      const authentication = gmailResponse.authentication;
      if (!authentication?.accessToken) {
        setStatus('error');
        Alert.alert('Gmail connection failed', 'Google did not return a Gmail access token.');
        return;
      }

      try {
        const session = await saveGmailMailboxSession(user.uid, authentication);
        await storeBackendGmailMailboxSession({
          email: session.email,
          access_token: session.session.accessToken,
          refresh_token: session.session.refreshToken,
          id_token: session.session.idToken,
          issued_at: session.session.issuedAt,
          expires_in: session.session.expiresIn,
          scope: session.session.scope,
          token_type: session.session.tokenType,
        });
        await completeOAuthLink(session.email);
        setStatus('idle');
      } catch (error) {
        setStatus('error');
        const message = error instanceof Error ? error.message : 'Gmail authorization completed, but the mailbox could not be linked.';
        Alert.alert('Gmail connection failed', message);
      }
    };

    void completeNativeGmailLink();
  }, [completeOAuthLink, gmailResponse, user]);

  const handleOAuthLink = async () => {
    setStatus('linking');
    try {
      if (Platform.OS === 'web') {
        const startUrl = await linkRealEmail();
        if (!startUrl) {
          throw new Error('A Gmail OAuth connector is not configured for this deployment yet.');
        }

        if (typeof window !== 'undefined' && typeof window.location?.assign === 'function') {
          window.location.assign(startUrl);
          return;
        }

        await Linking.openURL(startUrl);
        return;
      }

      if (!gmailRequest) {
        Alert.alert('Gmail unavailable', 'The Google Gmail authorization request is not ready yet.');
        return;
      }

      await promptGmailAsync({
        showInRecents: true,
      });
    } catch (error) {
      setStatus('error');
      const message = error instanceof Error ? error.message : 'Gmail authorization could not be started.';
      Alert.alert('Gmail connection failed', message);
    }
  };

  return (
    <View style={[styles.card, isMobile && styles.cardMobile]}>
      <View style={styles.headerRow}>
        <View style={[styles.iconWrap, isMobile && styles.iconWrapMobile, linkedEmails.length > 0 && styles.iconWrapActive]}>
          {linkedEmails.length > 0 ? <Bot color={palette.success} size={24} /> : <Mail color={palette.primary} size={24} />}
        </View>
        <View style={{ flex: 1 }}>
          <Text style={[styles.title, isMobile && styles.titleMobile]}>Email Protection Bot</Text>
          <Text style={styles.eyebrow}>Real-time inbox synchronization</Text>
        </View>
      </View>

      {status === 'linking' ? (
        <View style={styles.loadingState}>
          <ActivityIndicator color={palette.primary} size="large" />
          <Text style={styles.loadingTitle}>Establishing secure link</Text>
          <Text style={styles.loadingBody}>Synchronizing protected inbox signals...</Text>
        </View>
      ) : (
        <>
          <Text style={[styles.description, isMobile && styles.descriptionMobile]}>
            Connect Gmail with native Google consent so the app can run pre-delivery threat shielding: inspect attached links, score legitimacy, and alert you on potential scams before interaction.
          </Text>

          <Pressable
            disabled={Platform.OS !== 'web' && !gmailRequest}
            onPress={handleOAuthLink}
            style={({ pressed }) => [
              styles.oauthButton,
              isMobile && styles.oauthButtonMobile,
              Platform.OS !== 'web' && !gmailRequest && styles.oauthButtonDisabled,
              pressed && styles.pressed,
            ]}
          >
            <View style={styles.googleBadge}>
              <Text style={styles.googleBadgeText}>G</Text>
            </View>
            <Text style={styles.oauthButtonText}>
              {Platform.OS === 'web' || gmailRequest ? 'Connect Gmail Securely' : 'Google Auth Unavailable'}
            </Text>
          </Pressable>

          <Text style={styles.oauthHint}>
            Gmail linking authenticates the mailbox, stores the Gmail session for secure sync, and unlocks actual inbox scanning plus automatic pre-delivery link inspection. Manual mailbox watchlists have been removed from the app.
          </Text>

          {oauthMessage ? (
            <View style={[styles.oauthStatusCard, oauthStatus === 'success' ? styles.oauthStatusSuccess : oauthStatus === 'error' ? styles.oauthStatusError : styles.oauthStatusProcessing]}>
              <Text style={styles.oauthStatusText}>{oauthMessage}</Text>
            </View>
          ) : null}

          {loading ? (
            <View style={styles.loadingState}>
              <ActivityIndicator color={palette.primary} size="small" />
              <Text style={styles.loadingBody}>Loading linked mailbox records...</Text>
            </View>
          ) : oauthLinkedEmails.length > 0 ? (
            <View style={styles.linkedList}>
              <Text style={styles.linkedTitle}>Linked Accounts</Text>
              {oauthLinkedEmails.map((linked) => (
                <View key={linked.email} style={styles.linkedItem}>
                  <View style={styles.linkedMeta}>
                    <View
                      style={[
                        styles.statusDot,
                        linked.status === 'active' && styles.statusActive,
                        linked.status === 'syncing' && styles.statusSyncing,
                        linked.status === 'error' && styles.statusError,
                      ]}
                    />
                    <View style={{ flex: 1 }}>
                      <Text style={styles.linkedEmail}>{linked.email}</Text>
                      <View style={styles.linkedStateRow}>
                        <Text style={[styles.linkedState, linked.status === 'error' && { color: palette.error }]}>
                          {linked.status === 'active'
                            ? 'Active'
                            : linked.status === 'syncing'
                              ? 'Syncing...'
                              : 'Connection Error'}
                        </Text>
                        {linked.status === 'error' ? (
                          <Pressable onPress={() => void retryEmail(linked.email)} style={styles.retryButton}>
                            <RefreshCw color={palette.primary} size={10} />
                            <Text style={styles.retryText}>Reconnect</Text>
                          </Pressable>
                        ) : null}
                        <Text style={styles.providerBadge}>Gmail Connected</Text>
                      </View>
                      {linked.lastSyncedAt ? (
                        <Text style={styles.syncedText}>
                          Last synced {new Date(linked.lastSyncedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </Text>
                      ) : null}
                      <View style={styles.mailboxMetaWrap}>
                        {linked.health ? (
                          <Text style={styles.mailboxMetaText}>
                            Health: {linked.health === 'healthy' ? 'Healthy' : linked.health === 'watch' ? 'Heightened Watch' : 'Degraded'}
                          </Text>
                        ) : null}
                        {linked.nextScheduledScanAt ? (
                          <Text style={styles.mailboxMetaText}>
                            Next sweep {new Date(linked.nextScheduledScanAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </Text>
                        ) : null}
                        {typeof linked.lastScannedCount === 'number' ? (
                          <Text style={styles.mailboxMetaText}>
                            Last pass: {linked.lastScannedCount} message{linked.lastScannedCount === 1 ? '' : 's'}
                            {typeof linked.lastAlertCount === 'number' ? `, ${linked.lastAlertCount} alert${linked.lastAlertCount === 1 ? '' : 's'}` : ''}
                          </Text>
                        ) : null}
                        {linked.topSignals?.[0] ? <Text style={styles.mailboxMetaText}>Signal: {linked.topSignals[0]}</Text> : null}
                        {linked.lastError ? <Text style={[styles.mailboxMetaText, styles.mailboxMetaError]}>{linked.lastError}</Text> : null}
                      </View>
                    </View>
                  </View>

                  <Pressable onPress={() => void removeEmail(linked.email)} style={({ pressed }) => [styles.trashButton, pressed && styles.pressed]}>
                    <Trash2 color={palette.primaryMuted} size={14} />
                  </Pressable>
                </View>
              ))}
            </View>
          ) : null}

          <View style={styles.footerRow}>
            <View style={styles.footerBadge}>
              <Shield color={palette.primaryMuted} size={12} />
              <Text style={styles.footerBadgeText}>OAuth 2.0 Secure</Text>
            </View>
            <View style={styles.footerBadge}>
              <Lock color={palette.primaryMuted} size={12} />
              <Text style={styles.footerBadgeText}>Encrypted Sync</Text>
            </View>
          </View>
        </>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: palette.surfaceLow,
    borderRadius: 32,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.38)',
    padding: 24,
    gap: 18,
    overflow: 'hidden',
    ...shadows.card,
  },
  cardMobile: {
    borderRadius: 28,
    padding: 20,
    gap: 16,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 14,
  },
  iconWrap: {
    width: 52,
    height: 52,
    borderRadius: 20,
    backgroundColor: 'rgba(187,198,226,0.1)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  iconWrapMobile: {
    width: 48,
    height: 48,
    borderRadius: 18,
  },
  iconWrapActive: {
    backgroundColor: 'rgba(39,198,122,0.16)',
  },
  title: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 22,
  },
  titleMobile: {
    fontSize: 18,
  },
  eyebrow: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    marginTop: 4,
    textTransform: 'uppercase',
  },
  description: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 14,
    lineHeight: 22,
  },
  descriptionMobile: {
    lineHeight: 21,
  },
  oauthButton: {
    borderRadius: 18,
    backgroundColor: palette.surfaceHighest,
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.45)',
    paddingHorizontal: 18,
    paddingVertical: 16,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
  },
  oauthButtonMobile: {
    paddingHorizontal: 16,
    paddingVertical: 14,
    gap: 10,
  },
  oauthButtonText: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  oauthButtonDisabled: {
    opacity: 0.5,
  },
  oauthHint: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 12,
    lineHeight: 18,
  },
  oauthStatusCard: {
    borderRadius: 16,
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderWidth: 1,
  },
  oauthStatusSuccess: {
    backgroundColor: 'rgba(39,198,122,0.1)',
    borderColor: 'rgba(39,198,122,0.28)',
  },
  oauthStatusError: {
    backgroundColor: 'rgba(255,92,82,0.1)',
    borderColor: 'rgba(255,92,82,0.28)',
  },
  oauthStatusProcessing: {
    backgroundColor: 'rgba(187,198,226,0.08)',
    borderColor: 'rgba(187,198,226,0.2)',
  },
  oauthStatusText: {
    color: palette.onSurface,
    fontFamily: fonts.bodyMedium,
    fontSize: 13,
    lineHeight: 19,
  },
  googleBadge: {
    width: 24,
    height: 24,
    borderRadius: 12,
    backgroundColor: '#FFFFFF',
    alignItems: 'center',
    justifyContent: 'center',
  },
  googleBadgeText: {
    color: '#4285F4',
    fontFamily: fonts.headlineBold,
    fontSize: 14,
  },
  linkedList: {
    gap: 10,
  },
  linkedTitle: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 10,
    letterSpacing: 2,
    textTransform: 'uppercase',
  },
  linkedItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
    padding: 16,
    borderRadius: 20,
    backgroundColor: 'rgba(50,53,60,0.3)',
    borderWidth: 1,
    borderColor: 'rgba(68,71,76,0.25)',
  },
  linkedMeta: {
    flex: 1,
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 12,
  },
  statusDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    marginTop: 6,
    backgroundColor: palette.primaryMuted,
  },
  statusActive: {
    backgroundColor: palette.success,
  },
  statusSyncing: {
    backgroundColor: palette.primary,
  },
  statusError: {
    backgroundColor: palette.error,
  },
  linkedEmail: {
    color: palette.onSurface,
    fontFamily: fonts.bodySemiBold,
    fontSize: 14,
  },
  linkedStateRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginTop: 4,
  },
  linkedState: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.4,
    textTransform: 'uppercase',
  },
  syncedText: {
    color: 'rgba(196,198,204,0.42)',
    fontFamily: fonts.body,
    fontSize: 11,
    marginTop: 4,
  },
  mailboxMetaWrap: {
    gap: 4,
    marginTop: 6,
  },
  mailboxMetaText: {
    color: palette.onSurfaceMuted,
    fontFamily: fonts.body,
    fontSize: 11,
    lineHeight: 16,
  },
  mailboxMetaError: {
    color: palette.error,
  },
  retryButton: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  retryText: {
    color: palette.primary,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  providerBadge: {
    color: palette.secondary,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.1,
    textTransform: 'uppercase',
  },
  trashButton: {
    padding: 8,
  },
  footerRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  footerBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  footerBadgeText: {
    color: palette.primaryMuted,
    fontFamily: fonts.headline,
    fontSize: 9,
    letterSpacing: 1.2,
    textTransform: 'uppercase',
  },
  loadingState: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: 32,
    gap: 10,
  },
  loadingTitle: {
    color: palette.onSurface,
    fontFamily: fonts.headlineBold,
    fontSize: 20,
  },
  loadingBody: {
    color: palette.primaryMuted,
    fontFamily: fonts.body,
    fontSize: 13,
  },
  pressed: {
    opacity: 0.92,
    transform: [{ scale: 0.985 }],
  },
});
