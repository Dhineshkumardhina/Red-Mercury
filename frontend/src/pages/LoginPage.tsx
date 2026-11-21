import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login, loginAsTester } = useAuth();

  const [email, setEmail] = useState('dhineshkumardhina@gmail.com');
  const [password, setPassword] = useState('XerovaDevPass2026!');
  const [role, setRole] = useState<'SecOps Lead' | 'Security Analyst' | 'Staff Engineer'>('SecOps Lead');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleInstantLaunch = async () => {
    setErrorMessage(null);
    setIsLoading(true);
    try {
      if (loginAsTester) {
        await loginAsTester();
      } else {
        await login('dhineshkumardhina@gmail.com', 'XerovaDevPass2026!', 'SecOps Lead');
      }
      navigate('/dashboard');
    } catch {
      setErrorMessage('Could not launch testing session. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);

    try {
      const res = await login(email, password, role);
      if (res.success) {
        navigate('/dashboard');
      } else {
        setErrorMessage(res.error || 'Failed to authenticate.');
      }
    } catch {
      setErrorMessage('An unexpected error occurred during authentication.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8 font-sans">
      <div className="sm:mx-auto sm:w-full sm:max-w-md text-center">
        <Link to="/" className="inline-flex items-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-xl bg-slate-900 flex items-center justify-center text-white shadow-xs">
            <svg className="w-4 h-4 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="font-semibold text-lg text-slate-900 tracking-tight">
            Red Mercury
          </span>
        </Link>
        <h2 className="text-xl font-bold text-slate-900 tracking-tight">
          Security Testing Console
        </h2>
        <p className="mt-1 text-xs text-slate-500 max-w-sm mx-auto">
          Instant access to code verification, vulnerability analysis, and pull request testing.
        </p>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-6 px-6 sm:px-8 shadow-xs rounded-xl border border-slate-200">

          {/* 1-Click Instant Testing Access */}
          <div className="mb-5">
            <button
              type="button"
              onClick={handleInstantLaunch}
              disabled={isLoading}
              className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold text-xs rounded-lg shadow-sm transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <span>1-Click Launch Testing Environment</span>
            </button>
            <p className="text-[11px] text-center text-emerald-800 font-medium mt-1.5 flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
              <span>Pre-loaded with sample repositories &amp; verified test findings</span>
            </p>
          </div>

          <div className="relative flex py-2 items-center mb-4">
            <div className="flex-grow border-t border-slate-200"></div>
            <span className="flex-shrink mx-3 text-slate-400 text-[10px] uppercase tracking-wider font-semibold">
              Or sign in with custom account
            </span>
            <div className="flex-grow border-t border-slate-200"></div>
          </div>

          {errorMessage && (
            <div className="mb-4 p-3 rounded-md bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-center gap-2">
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-xs font-medium text-slate-700">
                Corporate Email
              </label>
              <div className="mt-1">
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 transition-all font-mono"
                  placeholder="user@company.com"
                />
              </div>
            </div>

            <div>
              <label htmlFor="role" className="block text-xs font-medium text-slate-700">
                Authorized Role
              </label>
              <select
                id="role"
                value={role}
                onChange={e => setRole(e.target.value as any)}
                className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 focus:outline-hidden focus:border-slate-400 transition-all"
              >
                <option value="SecOps Lead">SecOps Lead (Approval &amp; Auto-Merge)</option>
                <option value="Security Analyst">Security Analyst (Triage &amp; Verify)</option>
                <option value="Staff Engineer">Staff Engineer (View &amp; Sandbox Inspect)</option>
              </select>
            </div>

            <div>
              <label htmlFor="pass" className="block text-xs font-medium text-slate-700">
                Password / SSO Token
              </label>
              <input
                id="pass"
                type="password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="mt-1 w-full px-3 py-2 bg-white border border-slate-200 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 transition-all font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-2 py-2 px-4 bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs rounded-lg shadow-2xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
            >
              {isLoading && (
                <svg className="w-3.5 h-3.5 animate-spin text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
              )}
              <span>{isLoading ? 'Verifying Session...' : 'Authenticate to Console'}</span>
            </button>
          </form>

          <div className="mt-5 text-center text-xs text-slate-500">
            Need an isolated organization workspace?{' '}
            <Link to="/register" className="font-medium text-slate-900 hover:underline">
              Register Organization
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
