import { createContext, useContext, useEffect, useState } from 'react';
import { Platform } from 'react-native';
import type { AppUser } from '../types';
import {
  type AppAuthUser,
  createUserWithEmailPassword,
  db,
  doc,
  signInWithGooglePopup,
  signInWithApplePopup,
  signInWithEmailPassword,
  createGoogleCredential,
  signInWithProviderCredential,
  setDoc,
  signOutCurrentUser,
  subscribeToAuthState,
  updateCurrentUserProfile,
} from '../firebase';

interface AuthContextType {
  user: AppUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginWithGoogle: () => Promise<void>;
  loginWithApple: () => Promise<void>;
  loginWithGoogleIdToken: (idToken: string) => Promise<void>;
  register: (displayName: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<AppUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const isBootstrapAdminEmail = (email: string | null, emailVerified: boolean) =>
    emailVerified && email?.toLowerCase() === 'mustealawal@gmail.com';

  useEffect(() => {
    const unsubscribe = subscribeToAuthState(async (firebaseUser: AppAuthUser | null) => {
      if (!firebaseUser) {
        setUser(null);
        setIsAdmin(false);
        setLoading(false);
        return;
      }

      setUser({
        uid: firebaseUser.uid,
        email: firebaseUser.email,
        displayName: firebaseUser.displayName,
        photoURL: firebaseUser.photoURL,
      });

      // Check Firebase custom claims for admin role
      try {
        const tokenResult = firebaseUser.getIdTokenResult ? await firebaseUser.getIdTokenResult() : { claims: {} };
        setIsAdmin(tokenResult.claims.admin === true || isBootstrapAdminEmail(firebaseUser.email, Boolean(firebaseUser.emailVerified)));
      } catch {
        setIsAdmin(isBootstrapAdminEmail(firebaseUser.email, Boolean(firebaseUser.emailVerified)));
      }

      void setDoc(
        doc(db, 'users', firebaseUser.uid),
        {
          uid: firebaseUser.uid,
          email: firebaseUser.email,
          displayName: firebaseUser.displayName || firebaseUser.email?.split('@')[0] || 'Aegis Analyst',
          photoURL: firebaseUser.photoURL,
          role: 'analyst',
          lastSeenAt: new Date().toISOString(),
        },
        { merge: true },
      );

      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      await signInWithEmailPassword(email.trim(), password);
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogle = async () => {
    setLoading(true);
    try {
      if (Platform.OS === 'web') {
        await signInWithGooglePopup();
        return;
      }

      throw new Error('Google sign-in popup is only available on web. Use the native Google sign-in flow on mobile.');
    } finally {
      setLoading(false);
    }
  };

  const loginWithApple = async () => {
    setLoading(true);
    try {
      if (Platform.OS === 'web') {
        await signInWithApplePopup();
        return;
      }

      throw new Error('Apple sign-in is currently available on the web build. Native Apple sign-in can be added next if you want the full iOS flow.');
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogleIdToken = async (idToken: string) => {
    setLoading(true);
    try {
      const credential = createGoogleCredential(idToken);
      await signInWithProviderCredential(credential);
    } finally {
      setLoading(false);
    }
  };

  const register = async (displayName: string, email: string, password: string) => {
    setLoading(true);
    try {
      const credential = await createUserWithEmailPassword(email.trim(), password);
      const trimmedName = displayName.trim();

      if (trimmedName) {
        await updateCurrentUserProfile({ displayName: trimmedName });
      }

      await setDoc(
        doc(db, 'users', credential.user.uid),
        {
          uid: credential.user.uid,
          email: credential.user.email,
          displayName: trimmedName || credential.user.email?.split('@')[0] || 'Aegis Analyst',
          photoURL: credential.user.photoURL,
          role: 'analyst',
          createdAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString(),
        },
        { merge: true },
      );
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    await signOutCurrentUser();
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, loginWithGoogle, loginWithApple, loginWithGoogleIdToken, register, logout, isAdmin }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
