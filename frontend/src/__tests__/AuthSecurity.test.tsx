import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import { api, clearApiCache, getCsrfToken } from '../services/api';

describe('Frontend Authentication & HttpOnly Cookie Session Security (SEC-03, SEC-08, SEC-09, SEC-16)', () => {
  beforeEach(() => {
    clearApiCache();
    localStorage.clear();
    document.cookie = 'rm_csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    vi.restoreAllMocks();
  });

  it('blocks unauthenticated users from protected /dashboard and never persists JWT to localStorage', async () => {
    const fetchMock = vi.fn(() =>
      Promise.resolve({
        ok: false,
        status: 401,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve({ error: { message: 'Unauthorized' } }),
      })
    );
    vi.stubGlobal('fetch', fetchMock);

    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Security Console Sign-In/i })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Security Overview' })).not.toBeInTheDocument();
    // Must NEVER auto-POST /api/v1/auth/login on mount
    const loginCalls = fetchMock.mock.calls.filter(([url]: any) => String(url).includes('/api/v1/auth/login'));
    expect(loginCalls.length).toBe(0);
    // Every fetch call must use credentials: 'include' for HttpOnly cookies
    for (const [, init] of fetchMock.mock.calls as any[]) {
      expect(init?.credentials).toBe('include');
    }
    expect(localStorage.getItem('redmercury_token')).toBeNull();
  });

  it('does not pre-fill credentials or expose 1-click tester bypass on /login', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve({
          ok: false,
          status: 401,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({}),
        })
      )
    );

    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    const emailInput = (await screen.findByLabelText(/Corporate Email/i)) as HTMLInputElement;
    const passInput = screen.getByLabelText(/Password \/ SSO Token/i) as HTMLInputElement;

    expect(emailInput.value).toBe('');
    expect(passInput.value).toBe('');
    expect(screen.queryByText(/1-Click Launch Testing Environment/i)).not.toBeInTheDocument();
  });

  it('does not silently call /api/v1/auth/register when login fails with 8+ char password (SEC-08)', async () => {
    const fetchMock = vi.fn((url: string) => {
      if (String(url).includes('/api/v1/auth/login')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ error: { message: 'Invalid email or password.' } }),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 401,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve({}),
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    const emailInput = await screen.findByLabelText(/Corporate Email/i);
    const passInput = screen.getByLabelText(/Password \/ SSO Token/i);
    const submitBtn = screen.getByRole('button', { name: /Authenticate to Console/i });

    await act(async () => {
      fireEvent.change(emailInput, { target: { value: 'typo.user@company.com' } });
      fireEvent.change(passInput, { target: { value: 'LongWrongPassword123!' } });
      fireEvent.click(submitBtn);
    });

    expect(await screen.findByText(/Invalid email or password/i)).toBeInTheDocument();
    const registerCalls = fetchMock.mock.calls.filter(([url]: any) => String(url).includes('/api/v1/auth/register'));
    expect(registerCalls.length).toBe(0);
    expect(localStorage.getItem('redmercury_token')).toBeNull();
  });

  it('restores cookie session via /auth/me, attaches X-CSRF-Token on logout, and preserves session on FindingsPage refresh', async () => {
    document.cookie = 'rm_csrf_token=csrf-test-token-123; path=/';
    expect(getCsrfToken()).toBe('csrf-test-token-123');

    const fetchMock = vi.fn((url: string) => {
      if (String(url).includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          headers: { get: () => 'application/json' },
          json: () =>
            Promise.resolve({
              id: 'usr-real-1',
              email: 'analyst@company.com',
              account_status: 'active',
              role: 'analyst',
            }),
        });
      }
      if (String(url).includes('/api/v1/auth/logout')) {
        return Promise.resolve({
          ok: true,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve({ success: true, message: 'Logged out' }),
        });
      }
      if (String(url).includes('/api/v1/findings') || String(url).includes('/api/v1/repositories')) {
        return Promise.resolve({
          ok: true,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve([]),
        });
      }
      return Promise.resolve({
        ok: true,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve({}),
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    render(
      <MemoryRouter initialEntries={['/findings']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Security Findings/i })).toBeInTheDocument();
    expect(localStorage.getItem('redmercury_token')).toBeNull();

    // Refresh FindingsPage -> must NOT trigger login or destroy session
    const refreshBtn = screen.getByRole('button', { name: /Refresh/i });
    await act(async () => {
      fireEvent.click(refreshBtn);
    });
    expect(screen.getByRole('heading', { level: 1, name: /Security Findings/i })).toBeInTheDocument();

    // Sign out -> sends POST /api/v1/auth/logout with credentials: 'include' and X-CSRF-Token header
    const signOutBtn = screen.getByRole('button', { name: 'Sign Out' });
    await act(async () => {
      fireEvent.click(signOutBtn);
    });

    expect(await screen.findByRole('heading', { name: /Security Console Sign-In/i })).toBeInTheDocument();
    const logoutCall = fetchMock.mock.calls.find(([url]: any) => String(url).includes('/api/v1/auth/logout')) as any;
    expect(logoutCall).toBeTruthy();
    expect(logoutCall[1]?.credentials).toBe('include');
    expect(logoutCall[1]?.headers?.['X-CSRF-Token']).toBe('csrf-test-token-123');
  });

  it('deduplicates concurrent 401 refresh calls and prevents infinite 401 retry loops (SEC-16)', async () => {
    document.cookie = 'rm_csrf_token=csrf-refresh-tok; path=/';
    let refreshCount = 0;
    let findingsAttempts = 0;
    let reposAttempts = 0;

    const fetchMock = vi.fn((url: string) => {
      const sUrl = String(url);
      if (sUrl.includes('/api/v1/auth/refresh')) {
        refreshCount += 1;
        return new Promise((resolve) =>
          setTimeout(
            () =>
              resolve({
                ok: true,
                status: 200,
                headers: { get: () => 'application/json' },
                json: () => Promise.resolve({ user: { id: 'u1', email: 'a@b.com', role: 'analyst' } }),
              }),
            20
          )
        );
      }
      if (sUrl.includes('/api/v1/findings')) {
        findingsAttempts += 1;
        if (findingsAttempts === 1) {
          return Promise.resolve({
            ok: false,
            status: 401,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve({ error: { message: 'Expired' } }),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve([]),
        });
      }
      if (sUrl.includes('/api/v1/repositories')) {
        reposAttempts += 1;
        if (reposAttempts === 1) {
          return Promise.resolve({
            ok: false,
            status: 401,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve({ error: { message: 'Expired' } }),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          headers: { get: () => 'application/json' },
          json: () => Promise.resolve([]),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 401,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve({ error: { message: 'Still 401' } }),
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    // Two concurrent protected calls both hit 401 -> only ONE /auth/refresh must fire!
    const [findings, repos] = await Promise.all([api.getFindings(), api.getRepositories(true)]);
    expect(findings).toEqual([]);
    expect(repos).toEqual([]);
    expect(refreshCount).toBe(1);

    // Persistent 401 after refresh must NOT loop infinitely (max 1 retry)
    await expect(api.getHealth()).rejects.toThrow();
    const healthCalls = fetchMock.mock.calls.filter(([url]: any) => String(url).includes('/api/v1/health'));
    expect(healthCalls.length).toBeLessThanOrEqual(2);
  });
});
