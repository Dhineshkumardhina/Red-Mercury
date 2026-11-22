import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import { setAuthToken } from '../services/api';

describe('Red Mercury Frontend Routes & Components', () => {
  beforeEach(() => {
    setAuthToken('mock-test-auth-token');
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'usr-dev-seed-001',
            email: 'dev@xerova.com',
            account_status: 'active',
            role: 'SecOps Lead',
          }),
        });
      }

      if (url.includes('/api/v1/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            status: 'ok',
            service: 'Red Mercury',
            version: '0.1.0',
            environment: 'development',
            database: { status: 'connected', dialect: 'sqlite' },
            uptime_seconds: 12.3,
          }),
        });
      }

      if (url.includes('/api/v1/repositories')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'repo-auth-gateway',
              name: 'xerova/auth-gateway',
              default_branch: 'main',
              health_score: 84,
              critical_count: 1,
              high_count: 2,
              medium_count: 4,
              low_count: 0,
              is_active: true,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ]),
        });
      }

      if (url.includes('/analyses')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([]),
        });
      }

      if (url.includes('/validation')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({}),
        });
      }

      if (url.includes('/prioritization')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            finding_id: 'FIND-418',
            original_scanner_severity: 'CRITICAL',
            contextual_priority: 'CRITICAL',
            priority_score: 85,
            evidence_completeness: 'PARTIAL',
            verification_status: 'PENDING',
            remediation_readiness: 'NO_VERIFIED_FIX',
          }),
        });
      }

      if (url.includes('/api/v1/findings/FIND-418')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'FIND-418',
            repo_id: 'repo-auth-gateway',
            cwe: 'CWE-89: SQL Injection',
            title: 'Raw SQL Query String Interpolation in user_query.py',
            severity: 'CRITICAL',
            scanner_name: 'Semgrep OSS',
            file_path: 'auth-gateway/src/dao/user_query.py',
            line_number: 42,
            status: 'open',
            confidence_score: 0.98,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          }),
        });
      }

      if (url.includes('/api/v1/findings')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'FIND-418',
              repo_id: 'repo-auth-gateway',
              cwe: 'CWE-89: SQL Injection',
              title: 'Raw SQL Query String Interpolation in user_query.py',
              severity: 'CRITICAL',
              scanner_name: 'Semgrep OSS',
              file_path: 'auth-gateway/src/dao/user_query.py',
              line_number: 42,
              status: 'open',
              confidence_score: 0.98,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
            },
          ]),
        });
      }

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      });
    }));
  });

  it('renders landing page on "/landing"', async () => {
    render(
      <MemoryRouter initialEntries={['/landing']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/Detect source vulnerabilities/i)).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /Launch Security Console/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: /Sign In/i })[0]).toBeInTheDocument();
  });

  it('renders login page on "/login"', async () => {
    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Security Testing Console|Sign-In/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Corporate Email/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Authenticate to Console/i })).toBeInTheDocument();
  });

  it('renders register page on "/register"', async () => {
    render(
      <MemoryRouter initialEntries={['/register']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Register AppSec Workspace/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Full Name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Work Email/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Initialize Workspace/i })).toBeInTheDocument();
  });

  it('renders dashboard with sidebar on "/dashboard"', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('button', { name: 'Dashboard' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Repositories' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Security Overview' })).toBeInTheDocument();
  });

  it('renders repositories inventory and handles navigation on "/repositories"', async () => {
    render(
      <MemoryRouter initialEntries={['/repositories']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Repositories/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add Repository/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search repository/i)).toBeInTheDocument();
  });

  it('renders findings hub on "/findings"', async () => {
    render(
      <MemoryRouter initialEntries={['/findings']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Security Findings/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/Search title, CWE/i)).toBeInTheDocument();
  });

  it('renders fix verification center on "/verification"', async () => {
    render(
      <MemoryRouter initialEntries={['/verification']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Fix Verification/i })).toBeInTheDocument();
  });

  it('renders evidence center on "/evidence"', async () => {
    render(
      <MemoryRouter initialEntries={['/evidence']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Evidence Center/i })).toBeInTheDocument();
  });

  it('renders settings on "/settings"', async () => {
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/System Telemetry|Security Gate Settings/i)).toBeInTheDocument();
    expect(screen.getByText(/AST Taint Verification/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero Hardcoded Secrets Policy/i)).toBeInTheDocument();
  });

  it('renders finding details on "/findings/:id"', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/FIND-418']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/Risk Prioritization/i)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Run AI Security Analysis|Generate Analysis/i }).length).toBeGreaterThan(0);
  });

  it('redirects unauthenticated users from protected routes to "/login"', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve({
      ok: false,
      status: 401,
      headers: { get: () => 'application/json' },
      json: () => Promise.resolve({ error: { message: 'Unauthorized' } }),
    })));
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Security Testing Console|Sign-In/i })).toBeInTheDocument();
  });
});
