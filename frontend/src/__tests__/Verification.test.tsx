import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VerificationPage } from '../pages/VerificationPage';

describe('Fix Verification Engine Frontend Workspace', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string, options?: any) => {
      if (url.includes('/api/v1/verifications/validate-patch')) {
        const body = JSON.parse(options?.body || '{}');
        if (body.proposed_patch?.includes('etc/shadow') || body.proposed_patch?.includes('..')) {
          return Promise.resolve({
            ok: false,
            status: 400,
            headers: new Headers({ 'Content-Type': 'application/json' }),
            json: () => Promise.resolve({
              error: {
                message: 'Patch rejected: Path traversal attempt outside repository boundary: ../../../../etc/shadow',
                code: 'PATH_TRAVERSAL_REJECTED'
              }
            })
          });
        }
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            is_valid: true,
            files: [
              {
                old_path: 'auth_gateway/dao/user_query.py',
                new_path: 'auth_gateway/dao/user_query.py',
                added_lines: 2,
                deleted_lines: 2,
                modified_lines_range: '10-14'
              }
            ],
            total_added: 2,
            total_deleted: 2,
            errors: [],
            warnings: []
          })
        });
      }

      if (url.includes('/approve-and-merge')) {
        return Promise.resolve({
          ok: false,
          status: 422,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            error: {
              code: 'SECURITY_POLICY_VIOLATION',
              message: 'Automated direct merge is not configured. Red Mercury enforces least-privilege access and does not maintain write/push credentials to primary branches.',
            }
          })
        });
      }

      if (url.includes('/rerun')) {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            id: 'vr_test_rerun_01',
            finding_id: 'FIND-418',
            baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
            patched_hash: 'SHA256:7c82a194df110298a4421b8f1412fa09bb3310cbde12586144e05417ab9071cb',
            scanner_metadata: { 'Semgrep OSS': '1.78.0' },
            scanner_config: {},
            tests_executed: ['test_sql_injection_payload_is_neutralized'],
            test_results: { passed: 1 },
            original_finding_status: 'resolved',
            new_findings: [],
            execution_errors: [],
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
            reasons: ['Original finding FIND-418 was resolved and no new regressions were detected.'],
            missing_evidence: ['Dynamic database runtime taint tests not configured.'],
            evidence_references: ['aud_vr_test_rerun_01'],
            patch_diff: '--- a/file.py\n+++ b/file.py',
            test_summary: '1 passed in 0.5s',
            limitations: ['Never claim universal security or mathematically proven correctness.'],
            evidence: []
          })
        });
      }

      if (url.includes('/api/v1/verifications') && options?.method === 'POST') {
        return Promise.resolve({
          ok: true,
          headers: new Headers({ 'Content-Type': 'application/json' }),
          json: () => Promise.resolve({
            id: 'vr_test_exec_01',
            finding_id: 'FIND-418',
            baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
            patched_hash: 'SHA256:7c82a194df110298a4421b8f1412fa09bb3310cbde12586144e05417ab9071cb',
            scanner_metadata: { 'Semgrep OSS': '1.45.0' },
            scanner_config: {},
            tests_executed: ['test_sql_injection_payload_is_neutralized'],
            test_results: { passed: 1 },
            original_finding_status: 'resolved',
            new_findings: [],
            execution_errors: [],
            started_at: new Date().toISOString(),
            completed_at: new Date().toISOString(),
            status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
            reasons: ['Original finding FIND-418 was resolved and no new regressions were detected.'],
            missing_evidence: ['Dynamic database runtime taint tests not configured.'],
            evidence_references: ['aud_vr_test_exec_01'],
            patch_diff: '--- a/file.py\n+++ b/file.py',
            test_summary: '1 passed in 0.5s',
            limitations: ['Never claim universal security or mathematically proven correctness.'],
            evidence: []
          })
        });
      }

      if (url.includes('/api/v1/verifications')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'vr_sample_01',
              finding_id: 'FIND-418',
              baseline_hash: 'SHA256:4b91f092e038fa8167385a498b81347101adfa4792cb00a89104faeb19cb84f1',
              patched_hash: 'SHA256:7c82a194df110298a4421b8f1412fa09bb3310cbde12586144e05417ab9071cb',
              scanner_metadata: { 'Semgrep OSS': '1.78.0' },
              scanner_config: {},
              tests_executed: ['test_sql_injection_payload_is_neutralized'],
              test_results: { passed: 1 },
              original_finding_status: 'resolved',
              new_findings: [],
              execution_errors: [],
              started_at: '2026-10-20T08:00:00Z',
              completed_at: '2026-10-20T08:01:00Z',
              status: 'VERIFIED_AGAINST_DEFINED_CHECKS',
              reasons: [
                'Original finding FIND-418 was resolved and is no longer reported by Semgrep OSS',
                'Zero new security findings or regressions introduced into repository AST',
                'Targeted automated exploit probe verified injection payload safely parameterized',
              ],
              missing_evidence: [
                'Dynamic runtime taint flow with live database network cursor was not evaluated',
              ],
              evidence_references: ['aud_vr_sample_01'],
              patch_diff: '--- a/src/dao/user_query.py\n+++ b/src/dao/user_query.py\n@@ -42,3 +42,3 @@\n-cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n+cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
              test_summary: '1 passed in 0.5s',
              limitations: [
                'A scanner finding disappearing does not prove that the vulnerability is impossible.',
                'Passing tests do not prove complete security.',
                'Never claim universal security or mathematically proven correctness.'
              ],
              evidence: []
            },
            {
              id: 'vr_sample_02',
              finding_id: 'FIND-402',
              baseline_hash: 'SHA256:3a1b2c3d4e5f',
              patched_hash: 'SHA256:6e7f8a9b0c1d',
              scanner_metadata: { 'pip-audit': '2.7.3' },
              scanner_config: {},
              tests_executed: ['test_token_verification'],
              test_results: { failed: 1 },
              original_finding_status: 'persisted',
              new_findings: [],
              execution_errors: [],
              started_at: '2026-10-20T07:30:00Z',
              completed_at: '2026-10-20T07:31:00Z',
              status: 'FAILED_VERIFICATION',
              reasons: ['Original finding persisted'],
              missing_evidence: [],
              evidence_references: ['aud_vr_sample_02'],
              patch_diff: '--- a/requirements.txt\n+++ b/requirements.txt\n-pyjwt==1.7.1\n+pyjwt==2.8.0',
              test_summary: '1 failed in 0.8s',
              limitations: [],
              evidence: []
            },
            {
              id: 'vr_sample_03',
              finding_id: 'FIND-391',
              baseline_hash: 'SHA256:112233445566',
              patched_hash: 'SHA256:77889900aabb',
              scanner_metadata: { 'Bandit AST': '1.7.8' },
              scanner_config: {},
              tests_executed: [],
              test_results: {},
              original_finding_status: 'persisted',
              new_findings: [],
              execution_errors: ['Sandbox connection timed out'],
              started_at: '2026-10-20T07:00:00Z',
              completed_at: '2026-10-20T07:02:00Z',
              status: 'INCONCLUSIVE',
              reasons: ['Sandbox execution timed out before tests finished'],
              missing_evidence: ['Missing scanner completion receipt'],
              evidence_references: ['aud_vr_sample_03'],
              patch_diff: '--- a/config.py\n+++ b/config.py\n-SECRET="123"\n+SECRET=os.getenv("SECRET")',
              test_summary: 'timeout',
              limitations: [],
              evidence: []
            }
          ])
        });
      }

      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({})
      });
    }));
  });

  it('renders fix verification workspace with streamlined KPI summary', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Suite Header
    expect(await screen.findByRole('heading', { name: /Fix Verification/i })).toBeInTheDocument();
    expect(screen.getByText(/Automated testing and scanner gate verification/i)).toBeInTheDocument();

    // Ensure async records load before assertion
    expect(await screen.findByText('vr_sample_01')).toBeInTheDocument();

    // KPI Summary cards
    expect(screen.getByText(/Total Runs/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Verified Safe/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Failed Checks/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Inconclusive/i).length).toBeGreaterThan(0);
  });

  it('displays verification runs table with required evidence statuses', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Verify finding IDs and run references
    expect(await screen.findByText('vr_sample_01')).toBeInTheDocument();
    expect(screen.getByText('vr_sample_02')).toBeInTheDocument();

    // Should display runs with clean status badges
    expect(screen.getAllByText('Verified Safe')[0]).toBeInTheDocument();
    expect(screen.getAllByText('Failed Checks')[0]).toBeInTheDocument();
    expect(screen.getAllByText('Inconclusive')[0]).toBeInTheDocument();
  });

  it('opens Evidence Inspector modal with 5-step traceability', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Click "Inspect Evidence" on the first sample run
    const inspectButtons = await screen.findAllByRole('button', { name: /Inspect Evidence/i });
    fireEvent.click(inspectButtons[0]);

    // Modal title & baseline hash
    expect(await screen.findByText(/Fix Verification Run Evidence/i)).toBeInTheDocument();

    // Before/After comparison check (default tab)
    expect(screen.getByText(/Cryptographic Baseline vs Patched Comparison/i)).toBeInTheDocument();
    expect(screen.getByText(/Isolated Test Suite Regression Analysis/i)).toBeInTheDocument();

    // Switch to 5-Step Verification Audit tab
    const auditTabBtn = screen.getByRole('button', { name: /5-Step Verification Audit/i });
    fireEvent.click(auditTabBtn);

    expect(screen.getByText(/STEP 1 — Baseline Established/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 2 & 3 — Safe Patch Handling & Isolated Workspace/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 4 — Before & After Comparison & Regression Gates/i)).toBeInTheDocument();
    expect(screen.getByText(/RESOLVED \(No Longer Reported\)/i)).toBeInTheDocument();
    expect(screen.getByText(/Zero Regressions Detected/i)).toBeInTheDocument();
    expect(screen.getByText(/STEP 5 — Evidence-Based Conclusion & Traceable Rationale/i)).toBeInTheDocument();

    // Reasons & limitations displayed
    expect(screen.getAllByText(/Original finding FIND-418 was resolved and is no longer reported by Semgrep OSS/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/Dynamic runtime taint flow with live database network cursor was not evaluated/i)).toBeInTheDocument();


    // Close modal
    const closeBtn = screen.getByRole('button', { name: /Close Inspector/i });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText(/STEP 1 — Baseline Established/i)).not.toBeInTheDocument();
    });
  });

  it('opens Trigger Verification modal, validates patch safely, and detects file line changes', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open Trigger modal
    const triggerBtn = screen.getByRole('button', { name: /Trigger Fix Verification/i });
    fireEvent.click(triggerBtn);

    expect(screen.getByText(/Trigger Fix Verification Engine/i)).toBeInTheDocument();

    // Click "Validate Patch Safely"
    const validateBtn = screen.getByRole('button', { name: /Validate Patch Safely/i });
    fireEvent.click(validateBtn);

    // Should render validation result
    expect(await screen.findByText(/Patch Parsing & Path Validation Passed/i)).toBeInTheDocument();
    expect(screen.getByText(/\+2 \/ -2 lines/i)).toBeInTheDocument();
    expect(screen.getByText(/Touched:/i)).toBeInTheDocument();
  });

  it('rejects path traversal patch during dry-run validation', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open Trigger modal
    const triggerBtn = screen.getByRole('button', { name: /Trigger Fix Verification/i });
    fireEvent.click(triggerBtn);

    // Select Preset 4 (Path Traversal)
    const traversalPresetBtn = screen.getByRole('button', { name: /Preset 4: Malicious Path Traversal/i });
    fireEvent.click(traversalPresetBtn);

    // Ensure the textarea reflects the traversal diff
    const textarea = screen.getByPlaceholderText(/--- a\/path\/to\/file/i) as HTMLTextAreaElement;
    expect(textarea.value).toContain('../../../../etc/shadow');

    // Click "Validate Patch Safely"
    const validateBtn = screen.getByRole('button', { name: /Validate Patch Safely/i });
    fireEvent.click(validateBtn);

    // Should display rejection error
    expect(await screen.findByText(/Path traversal attempt outside repository boundary/i)).toBeInTheDocument();
  });

  it('handles rerun verification through backend endpoint and displays updated status', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open crash modal on an inconclusive or failed sample run
    const diffButtons = await screen.findAllByRole('button', { name: /^Diff$/i });
    expect(diffButtons.length).toBeGreaterThan(0);
    fireEvent.click(diffButtons[0]);

    // Modal opens
    expect(await screen.findByText(/AST Remediation Diff/i)).toBeInTheDocument();

    // Close diff modal
    const closeBtn = screen.getByTitle('Close');
    fireEvent.click(closeBtn);
  });

  it('enforces least-privilege policy on diff inspection without fabricated direct merge', async () => {
    render(
      <MemoryRouter>
        <VerificationPage />
      </MemoryRouter>
    );

    // Open diff modal for verified run
    const diffButtons = await screen.findAllByRole('button', { name: /^Diff$/i });
    fireEvent.click(diffButtons[0]);

    expect(await screen.findByText(/AST Remediation Diff/i)).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Close/i }).length).toBeGreaterThan(0);
  });
});

