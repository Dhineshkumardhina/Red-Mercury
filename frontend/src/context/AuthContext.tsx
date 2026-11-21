import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import {
  loginWithCredentials,
  registerUser,
  getCurrentUser,
  logoutUser,
  getAuthToken,
  setAuthToken,
} from '../services/api';

export interface UserSession {
  id: string;
  email: string;
  fullName: string;
  role: 'SecOps Lead' | 'Security Analyst' | 'Staff Engineer';
  organization: string;
  isAuthenticated: boolean;
  sessionType: 'standard' | 'enterprise';
}

export interface AuthContextType {
  user: UserSession | null;
  isLoading: boolean;
  login: (email: string, password: string, role?: UserSession['role']) => Promise<{ success: boolean; error?: string }>;
  register: (fullName: string, email: string, password: string, organization: string) => Promise<{ success: boolean; error?: string }>;
  loginAsTester: () => Promise<{ success: boolean }>;
  logout: () => Promise<void>;
}

const defaultTester: UserSession = {
  id: 'ade14bbe-e0f0-4c8e-beff-ff9f720fe288',
  email: 'dhineshkumardhina@gmail.com',
  fullName: 'Dhinesh Kumar',
  role: 'SecOps Lead',
  organization: 'Red Mercury Security Workspace',
  isAuthenticated: true,
  sessionType: 'standard',
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Restore authenticated session on initial mount or automatically provision instant tester session
  useEffect(() => {
    let isMounted = true;
    const initAuth = async () => {
      const existingToken = getAuthToken();
      if (existingToken) {
        try {
          const profile = await getCurrentUser();
          if (isMounted && profile?.id) {
            setUser({
              id: profile.id,
              email: profile.email,
              fullName: profile.email === 'dhineshkumardhina@gmail.com' ? 'Dhinesh Kumar' : profile.email.split('@')[0].replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase()),
              role: 'SecOps Lead',
              organization: 'Red Mercury Security Workspace',
              isAuthenticated: true,
              sessionType: 'standard',
            });
            setIsLoading(false);
            return;
          }
        } catch {
          // Token expired or invalid, fall through to auto-authenticate
        }
      }

      // Auto-authenticate into testing environment without login friction
      try {
        const res = await loginWithCredentials('dhineshkumardhina@gmail.com', 'XerovaDevPass2026!');
        if (isMounted && res?.access_token && res?.user) {
          setUser({
            id: res.user.id,
            email: res.user.email,
            fullName: 'Dhinesh Kumar',
            role: 'SecOps Lead',
            organization: 'Red Mercury Security Workspace',
            isAuthenticated: true,
            sessionType: 'standard',
          });
          setIsLoading(false);
          return;
        }
      } catch {
        // Standalone offline testing mode
        if (isMounted) {
          setUser(defaultTester);
        }
      }

      if (isMounted) {
        setIsLoading(false);
      }
    };

    initAuth();
    return () => {
      isMounted = false;
    };
  }, []);

  const loginAsTester = async () => {
    setIsLoading(true);
    try {
      const res = await loginWithCredentials('dhineshkumardhina@gmail.com', 'XerovaDevPass2026!');
      if (res?.access_token && res?.user) {
        setUser({
          id: res.user.id,
          email: res.user.email,
          fullName: 'Dhinesh Kumar',
          role: 'SecOps Lead',
          organization: 'Red Mercury Security Workspace',
          isAuthenticated: true,
          sessionType: 'standard',
        });
        return { success: true };
      }
    } catch {
      setUser(defaultTester);
    } finally {
      setIsLoading(false);
    }
    return { success: true };
  };

  const login = async (
    email: string,
    password: string,
    role: UserSession['role'] = 'SecOps Lead'
  ) => {
    if (!email || !password) {
      return { success: false, error: 'Email and password are required.' };
    }
    try {
      const res = await loginWithCredentials(email, password);
      if (res?.access_token && res?.user) {
        const newUser: UserSession = {
          id: res.user.id,
          email: res.user.email,
          fullName: email.split('@')[0].replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase()),
          role,
          organization: 'Red Mercury Testing Workspace',
          isAuthenticated: true,
          sessionType: 'standard',
        };
        setUser(newUser);
        return { success: true };
      }
      return { success: false, error: 'Authentication failed.' };
    } catch (err: any) {
      // Auto-register new practitioner accounts seamlessly if password meets minimum length
      if (password.length >= 8) {
        try {
          await registerUser(email, password);
          const res = await loginWithCredentials(email, password);
          if (res?.access_token && res?.user) {
            const newUser: UserSession = {
              id: res.user.id,
              email: res.user.email,
              fullName: email.split('@')[0].replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase()),
              role,
              organization: 'Red Mercury Testing Workspace',
              isAuthenticated: true,
              sessionType: 'standard',
            };
            setUser(newUser);
            return { success: true };
          }
        } catch {
          // Return original error if registration fails
        }
      }
      return { success: false, error: err.message || 'Authentication failed. Please verify credentials or register a new workspace.' };
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
      if (res?.access_token && res?.user) {
        const newUser: UserSession = {
          id: res.user.id,
          email: res.user.email,
          fullName,
          role: 'Security Analyst',
          organization,
          isAuthenticated: true,
          sessionType: 'standard',
        };
        setUser(newUser);
        return { success: true };
      }
      return { success: false, error: 'Registration failed.' };
    } catch (err: any) {
      return { success: false, error: err.message || 'Registration failed.' };
    }
  };

  const logout = async () => {
    await logoutUser();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, isLoading, login, register, loginAsTester, logout }}>
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
