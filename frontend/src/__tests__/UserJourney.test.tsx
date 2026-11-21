import { render, screen, fireEvent, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from '../App';
import { setAuthToken } from '../services/api';

describe('Red Mercury — End-to-End User Journey & Resilience Tests', () => {
  const mockRepo = {
    id: 'repo-payment-svc',
    name: 'xerova/payment-service',
    default_branch: 'main',
    health_score: 91,
    critical_count: 1,
    high_count: 1,
    medium_count: 0,
    low_count: 0,
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const mockFinding = {
    id: 'FND-SQL-001',
    repo_id: 'repo-payment-svc',
    cwe: 'CWE-89: SQL Injection',
    title: 'Unsanitized SQL Query Parameter in transaction_dao.py',
    severity: 'HIGH',
    scanner_name: 'Bandit AST',
    file_path: 'services/transaction_dao.py',
    line_number: 42,
    status: 'open',
    confidence_score: 0.94,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  beforeEach(() => {
    (window as any).__SCAN_POLL_INTERVAL__ = 20;
    setAuthToken('valid-user-test-token');
    vi.stubGlobal('fetch', vi.fn((url: string, options?: any) => {
      // 1. Health check
      if (url.includes('/api/v1/health')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            status: 'ok',
            service: 'Red Mercury',
            version: '1.0.0',
            database: { status: 'connected', dialect: 'sqlite' },
          }),
        });
      }

      // 2. Auth /me
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'usr-secops-001',
            email: 'dhineshkumardhina@gmail.com',
            account_status: 'active',
            role: 'SecOps Lead',
          }),
        });
      }

      // 3. Auth login
      if (url.includes('/api/v1/auth/login')) {
        const body = JSON.parse(options?.body || '{}');
        if (body.password === 'WrongPassword!') {
          return Promise.resolve({
            ok: false,
            status: 401,
            json: () => Promise.resolve({
              error: { code: 'UNAUTHORIZED', message: 'Authentication failed. Please verify credentials.' },
            }),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            access_token: 'valid-user-test-token',
            token_type: 'bearer',
            user: {
              id: 'usr-secops-001',
              email: body.email,
              role: 'SecOps Lead',
              account_status: 'active',
            },
          }),
        });
      }

      // 4. Auth logout
      if (url.includes('/api/v1/auth/logout')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ success: true, message: 'Logged out successfully.' }),
        });
      }

      // 5. Scanner Tools
      if (url.includes('/api/v1/scans/tools')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            { name: 'bandit', display_name: 'Bandit AST', is_available: true, category: 'sast' },
            { name: 'secret_detector', display_name: 'Credential Detector', is_available: true, category: 'secrets' },
          ]),
        });
      }

      // 6. Scans (trigger)
      if (url.endsWith('/api/v1/scans') && options?.method === 'POST') {
        const body = JSON.parse(options?.body || '{}');
        return Promise.resolve({
          ok: true,
          status: 202,
          json: () => Promise.resolve({
            id: 'scan-run-001',
            repository_id: body.repository_id || mockRepo.id,
            status: 'queued',
            is_complete: false,
          }),
        });
      }

      // 7. Scan status polling
      if (url.includes('/api/v1/scans/scan-run-001') && !url.includes('/results')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'scan-run-001',
            status: 'completed',
            is_complete: true,
          }),
        });
      }

      // 8. Scan results
      if (url.includes('/api/v1/scans/scan-run-001/results')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'scan-run-001',
            status: 'completed',
            findings_count: 1,
            scanners: [{ scanner_name: 'Bandit AST', status: 'SUCCESS', findings_count: 1 }],
          }),
        });
      }

      // 9. Repositories
      if (url.includes('/api/v1/repositories')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([mockRepo]),
        });
      }

      // 10. Prioritization queue
      if (url.includes('/api/v1/prioritization/queue')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([]),
        });
      }

      // 11. Prioritization item
      if (url.includes('/prioritization')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            finding_id: 'FND-SQL-001',
            original_scanner_severity: 'HIGH',
            contextual_priority: 'HIGH',
            priority_score: 82,
            evidence_completeness: 'PARTIAL',
            verification_status: 'PENDING',
            remediation_readiness: 'READY_FOR_REVIEW',
          }),
        });
      }

      // 12. Analyses & validation
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

      // 13. Findings list & detail
      if (url.includes('/api/v1/findings/FND-SQL-001')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockFinding),
        });
      }
      if (url.includes('/api/v1/findings')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([mockFinding]),
        });
      }

      // 13. Verification Runs
      if (url.includes('/api/v1/verifications')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'vr-001',
              finding_id: 'FND-SQL-001',
              status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
              baseline_hash: 'a1b2c3d4e5f6',
              patched_hash: 'f6e5d4c3b2a1',
              reasons: ['SQL Injection vector eliminated by parameterized query.'],
              test_summary: '100% tests passed',
              completed_at: new Date().toISOString(),
            },
          ]),
        });
      }

      // 14. Reports export
      if (url.includes('/api/v1/evidence/reports/findings')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            report_title: 'Security Findings Report - payment-service',
            content: '{"version": "2.1.0", "runs": []}',
            metadata: { format: 'json', total_findings: 1 },
          }),
        });
      }

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve([]),
      });
    }));
  });

  it('Journey: rejects invalid credentials on login', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url.includes('/api/v1/auth/login')) {
        return Promise.resolve({
          ok: false,
          status: 401,
          json: () => Promise.resolve({
            error: { code: 'UNAUTHORIZED', message: 'Authentication failed. Please verify credentials.' },
          }),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 401,
        json: () => Promise.resolve({}),
      });
    }));

    setAuthToken(null);
    render(
      <MemoryRouter initialEntries={['/login']}>
        <App />
      </MemoryRouter>
    );

    const emailInput = await screen.findByLabelText(/Corporate Email/i);
    const passwordInput = screen.getByLabelText(/Password \/ SSO Token/i);
    const submitBtn = screen.getByRole('button', { name: /Authenticate to Console/i });

    await act(async () => {
      fireEvent.change(emailInput, { target: { value: 'wrong@company.com' } });
      fireEvent.change(passwordInput, { target: { value: 'WrongPassword!' } });
      fireEvent.click(submitBtn);
    });

    expect(await screen.findByText(/Authentication failed/i)).toBeInTheDocument();
  });

  it('Journey: full happy path from dashboard to scan, findings, and export', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    // 1. Dashboard displays navigation and overview
    expect(await screen.findByRole('button', { name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Security Overview' })).toBeInTheDocument();
    expect(await screen.findByText(/xerova\/payment-service/i)).toBeInTheDocument();

    // 2. Open Scan Modal from dashboard
    const runScanBtn = screen.getByRole('button', { name: /Run Scan/i });
    expect(runScanBtn).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(runScanBtn);
    });

    // Scan modal opens
    expect(await screen.findByText(/Run Security Analysis/i)).toBeInTheDocument();

    // Trigger start scan
    const startScanBtn = screen.getByRole('button', { name: /Execute Security Scan/i });
    await act(async () => {
      fireEvent.click(startScanBtn);
    });

    // Observe completion and close modal
    const finishBtn = await screen.findByRole('button', { name: /View Findings & Posture/i }, { timeout: 3000 });
    expect(finishBtn).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(finishBtn);
    });

    // 3. Open Export Modal from dashboard
    const exportBtn = screen.getByRole('button', { name: 'Export' });
    expect(exportBtn).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(exportBtn);
    });

    expect(await screen.findByText(/Export AppSec Compliance & Audit Trail/i)).toBeInTheDocument();
    const downloadBtn = screen.getByRole('button', { name: /Download SARIF|Download/i });
    expect(downloadBtn).toBeInTheDocument();
  });

  it('Journey: view finding details, risk prioritization, and evidence review', async () => {
    render(
      <MemoryRouter initialEntries={['/findings/FND-SQL-001']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByText(/Unsanitized SQL Query Parameter/i)).toBeInTheDocument();
    expect(screen.getByText(/CWE-89/i)).toBeInTheDocument();
    expect(screen.getAllByText(/transaction_dao.py/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Risk Prioritization/i)).toBeInTheDocument();
  });

  it('Journey: view fix verification runs with verified check status', async () => {
    render(
      <MemoryRouter initialEntries={['/verification']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('heading', { name: /Fix Verification/i })).toBeInTheDocument();
    expect(await screen.findByText('FND-SQL-001')).toBeInTheDocument();
    expect(screen.getByText(/SQL Injection vector eliminated/i)).toBeInTheDocument();
  });

  it('Journey: sign out terminates session and redirects to /login', async () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('button', { name: 'Dashboard' })).toBeInTheDocument();

    const signOutBtn = screen.getByRole('button', { name: 'Sign Out' });
    expect(signOutBtn).toBeInTheDocument();

    await act(async () => {
      fireEvent.click(signOutBtn);
    });

    expect(await screen.findByRole('heading', { name: /Security Testing Console|Sign-In/i })).toBeInTheDocument();
  });

  it('Failure Scenario: failed scan displays error state and never fabricates success', async () => {
    vi.stubGlobal('fetch', vi.fn((url: string, options?: any) => {
      if (url.includes('/api/v1/auth/me')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ id: 'usr-1', email: 'a@x.com', account_status: 'active', role: 'SecOps Lead' }),
        });
      }
      if (url.includes('/api/v1/health')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'ok' }) });
      }
      if (url.includes('/api/v1/repositories')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([mockRepo]) });
      }
      if (url.includes('/api/v1/scans/tools')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve([{ name: 'bandit', display_name: 'Bandit AST', category: 'sast', is_available: true }]) });
      }
      if (url.endsWith('/api/v1/scans') && options?.method === 'POST') {
        return Promise.resolve({
          ok: false,
          status: 400,
          json: () => Promise.resolve({
            error: { code: 'SCAN_FAILED', message: 'Repository workspace path is not set or inaccessible.' },
          }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve([]) });
    }));

    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <App />
      </MemoryRouter>
    );

    expect(await screen.findByRole('button', { name: 'Dashboard' })).toBeInTheDocument();

    const runScanBtn = screen.getByRole('button', { name: /Run Scan/i });
    await act(async () => {
      fireEvent.click(runScanBtn);
    });

    expect(await screen.findByText(/Run Security Analysis/i)).toBeInTheDocument();

    const startScanBtn = screen.getByRole('button', { name: /Execute Security Scan/i });
    await act(async () => {
      fireEvent.click(startScanBtn);
    });

    // Error banner should be displayed, NOT success
    expect(await screen.findByText(/Repository workspace path is not set or inaccessible/i)).toBeInTheDocument();
    expect(screen.queryByText(/View Findings & Posture/i)).not.toBeInTheDocument();
  });
});
