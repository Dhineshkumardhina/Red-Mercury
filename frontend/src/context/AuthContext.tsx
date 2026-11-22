import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import {
  loginWithCredentials,
  registerUser,
  getCurrentUser,
  logoutUser,
  clearApiCache,
} from '../services/api';

export interface UserSession {
  id: string;
  email: string;
  fullName: string;
  role: string;
  organization: string;
  isAuthenticated: boolean;
  sessionType: 'standard' | 'enterprise';
}

export interface AuthContextType {
  user: UserSession | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  register: (fullName: string, email: string, password: string, organization: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
}

function formatDisplayName(email: string): string {
  const localPart = (email || '').split('@')[0] || 'User';
  return localPart
    .replace(/[._-]+/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Restore authenticated session strictly via HttpOnly cookie verification (GET /api/v1/auth/me)
  useEffect(() => {
    let isMounted = true;
    const initAuth = async () => {
      try {
        const profile = await getCurrentUser();
        if (isMounted && profile?.id) {
          setUser({
            id: profile.id,
            email: profile.email,
            fullName: formatDisplayName(profile.email),
            role: profile.role || 'analyst',
            organization: 'Red Mercury Security Workspace',
            isAuthenticated: true,
            sessionType: 'standard',
          });
          setIsLoading(false);
          return;
        }
      } catch {
        // Unauthenticated or expired session: require explicit sign-in
      }

      if (isMounted) {
        setUser(null);
        setIsLoading(false);
      }
    };

    const handleSessionExpired = () => {
      if (isMounted) {
        clearApiCache();
        setUser(null);
      }
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('redmercury:session-expired', handleSessionExpired);
    }

    initAuth();
    return () => {
      isMounted = false;
      if (typeof window !== 'undefined') {
        window.removeEventListener('redmercury:session-expired', handleSessionExpired);
      }
    };
  }, []);

  const login = async (email: string, password: string) => {
    if (!email || !password) {
      return { success: false, error: 'Email and password are required.' };
    }
    try {
      const res = await loginWithCredentials(email, password);
      if (res?.user?.id) {
        const newUser: UserSession = {
          id: res.user.id,
          email: res.user.email,
          fullName: formatDisplayName(res.user.email),
          role: res.user.role || 'analyst',
          organization: 'Red Mercury Security Workspace',
          isAuthenticated: true,
          sessionType: 'standard',
        };
        setUser(newUser);
        return { success: true };
      }
      return { success: false, error: 'Authentication failed.' };
    } catch (err: any) {
      return {
        success: false,
        error: err?.message || 'Authentication failed. Please verify your credentials.',
      };
    }
  };

  const register = async (
    fullName: string,
    email: string,
    password: string,
    organization: string
  ) => {
    if (!email || !password || !fullName || !organization) {
      return { success: false, error: 'All fields including password are required for registration.' };
    }
    if (password.length < 8) {
      return { success: false, error: 'Password must be at least 8 characters long.' };
    }

    try {
      const res = await registerUser(email, password);
      if (res?.user?.id) {
        const newUser: UserSession = {
          id: res.user.id,
          email: res.user.email,
          fullName,
          role: res.user.role || 'analyst',
          organization,
          isAuthenticated: true,
          sessionType: 'standard',
        };
        setUser(newUser);
        return { success: true };
      }
      return { success: false, error: 'Registration failed.' };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Registration failed.' };
    }
  };

  const logout = async () => {
    try {
      await logoutUser();
    } finally {
      clearApiCache();
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
