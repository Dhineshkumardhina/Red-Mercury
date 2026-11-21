import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { AiSecurityAnalystCard } from '../components/findings/AiSecurityAnalystCard';
import { AiSecurityAnalyzerScreen } from '../components/analyzer/AiSecurityAnalyzerScreen';
import { AnalysisResult, api } from '../services/api';

describe('AiSecurityAnalystCard Component', () => {
  const mockAnalysis: AnalysisResult = {
    id: 'ANALYSIS-101',
    finding_id: 'FIND-418',
    vulnerability_category: 'CWE-89: SQL Injection',
    plain_language_explanation: 'User input is directly interpolated into a raw SQL query string without parameterized bindings.',
    likely_root_cause: 'String formatting f-string used in DAO query builder without parameter placeholders.',
    potential_impact: 'Full database read and write access, bypassing authentication and authorization controls.',
    relevant_code_evidence: [
      'cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\'")',
      'tenant_id parameter from request query arguments'
    ],
    suggested_remediation: [
      'Replace f-string with parameterized query placeholders %s',
      'Pass parameters as a tuple: cursor.execute("SELECT ... WHERE tenant_id = %s", (tenant_id,))'
    ],
    suggested_targeted_tests: [
      'test_sql_injection_payload_in_tenant_id_rejected()',
      'test_normal_tenant_id_retrieves_expected_record()'
    ],
    missing_context: [
      'Router middleware authorization not captured in 30-line window'
    ],
    limitations: [
      'Static analysis only. Runtime database permission level cannot be verified.'
    ],
    ai_model: 'gemini-1.5-flash',
    analysis_timestamp: '2026-10-11T10:00:00Z',
    confidence: 'HIGH',
    is_exploitable_claim_supported: true,
    requires_human_review: true,
    user_authorized: true
  };

  it('renders AI Security Analyst Card with mandatory human review warning', () => {
    render(
      <AiSecurityAnalystCard
        analysis={mockAnalysis}
        isLoading={false}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    // Warning banner
    expect(screen.getByText(/AI-Generated Security Analysis — Requires Human Review/i)).toBeInTheDocument();
    expect(screen.getByText(/must be validated by security engineers prior to implementation/i)).toBeInTheDocument();

    // Model and metadata
    expect(screen.getByText('gemini-1.5-flash')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();

    // Exploitability status
    expect(screen.getByText(/Exploitability Supported by Static Flow/i)).toBeInTheDocument();

    // Plain-language explanation, root cause, impact
    expect(screen.getByText(/User input is directly interpolated into a raw SQL query string/i)).toBeInTheDocument();
    expect(screen.getByText(/String formatting f-string used in DAO query builder/i)).toBeInTheDocument();
    expect(screen.getByText(/Full database read and write access/i)).toBeInTheDocument();

    // Remediations and tests
    expect(screen.getByText(/Replace f-string with parameterized query placeholders/i)).toBeInTheDocument();
    expect(screen.getByText(/test_sql_injection_payload_in_tenant_id_rejected\(\)/i)).toBeInTheDocument();

    // Caveats
    expect(screen.getByText(/Router middleware authorization not captured/i)).toBeInTheDocument();
    expect(screen.getByText(/Static analysis only/i)).toBeInTheDocument();
  });

  it('displays exploitability unproven badge when claim is not supported', () => {
    const unprovenAnalysis: AnalysisResult = {
      ...mockAnalysis,
      is_exploitable_claim_supported: false,
    };

    render(
      <AiSecurityAnalystCard
        analysis={unprovenAnalysis}
        isLoading={false}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Exploitability Unproven \/ Context Incomplete/i)).toBeInTheDocument();
  });

  it('handles user authorization toggle state', () => {
    const onToggle = vi.fn();
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={false}
        error={null}
        userAuthorized={false}
        onToggleAuthorization={onToggle}
        onRunAnalysis={vi.fn()}
      />
    );

    // Authorization hold message shown
    expect(screen.getByText(/Authorization Hold:/i)).toBeInTheDocument();
    expect(screen.getByText(/private repository content will not be sent/i)).toBeInTheDocument();

    // Checkbox interaction
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).not.toBeChecked();
    fireEvent.click(checkbox);
    expect(onToggle).toHaveBeenCalledWith(true);
  });

  it('renders error message when analysis engine encounters error', () => {
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={false}
        error="Backend AI rate limit exceeded or connection timed out."
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Analyst Service Notice:/i)).toBeInTheDocument();
    expect(screen.getByText(/Backend AI rate limit exceeded or connection timed out/i)).toBeInTheDocument();
  });

  it('renders loading spinner when analysis is in progress', () => {
    render(
      <AiSecurityAnalystCard
        analysis={null}
        isLoading={true}
        error={null}
        userAuthorized={true}
        onToggleAuthorization={vi.fn()}
        onRunAnalysis={vi.fn()}
      />
    );

    expect(screen.getByText(/Synthesizing AI Security Assessment.../i)).toBeInTheDocument();
  });
});

describe('AiSecurityAnalyzerScreen Component - API Integration & Integrity', () => {
  it('loads vulnerable and safe code presets and updates analysis output', () => {
    render(<AiSecurityAnalyzerScreen />);

    // Initially shows default example
    expect(screen.getByText(/Security Vulnerability Detected/i)).toBeInTheDocument();

    // Click "Safe Code" preset
    const safeBtn = screen.getByRole('button', { name: /Safe Code/i });
    fireEvent.click(safeBtn);

    expect(screen.getByText(/Safe Parameterized Implementation/i)).toBeInTheDocument();

    // Click "Vulnerable Code" preset
    const vulnBtn = screen.getByRole('button', { name: /Vulnerable Code/i });
    fireEvent.click(vulnBtn);

    expect(screen.getByText(/Security Vulnerability Detected/i)).toBeInTheDocument();
  });

  it('calls /api/v1/analyze-finding with normalized uppercase severity and renders verified backend response on success', async () => {
    const mockSuccessResponse: AnalysisResult = {
      id: 'ANALYSIS-BACKEND-777',
      finding_id: 'PATCH-ANALYSIS',
      vulnerability_category: 'CWE-89: SQL Injection',
      plain_language_explanation: 'Real backend vulnerability triage explanation from Gemini 3.8 Flash.',
      likely_root_cause: 'Real backend root cause: Unsanitized tenant parameter formatted directly into query string.',
      potential_impact: 'Critical unauthorized database access.',
      relevant_code_evidence: ['cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\'")'],
      suggested_remediation: ['Use parameterized query bindings.'],
      suggested_targeted_tests: ['test_sql_injection_defense()'],
      missing_context: [],
      limitations: ['Verified by static dataflow inspection.'],
      ai_model: 'gemini-1.5-flash',
      analysis_timestamp: '2026-10-19T10:00:00Z',
      confidence: 'HIGH',
      is_exploitable_claim_supported: true,
      requires_human_review: true,
      user_authorized: true,
    };

    const spy = vi.spyOn(api, 'analyzeFinding').mockResolvedValueOnce(mockSuccessResponse);

    render(<AiSecurityAnalyzerScreen />);

    // Trigger analysis
    const executeBtn = screen.getByRole('button', { name: /Analyze Code Security/i });
    fireEvent.click(executeBtn);

    // Wait for success output
    expect(await screen.findByText(/Real backend vulnerability triage explanation from Gemini 3.8 Flash/i)).toBeInTheDocument();

    // Verify spy was called with properly formatted/uppercased severity
    expect(spy).toHaveBeenCalledTimes(1);
    const calledPayload = spy.mock.calls[0][0];
    expect(calledPayload.scanner_severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);

    spy.mockRestore();
  });

  it('handles backend API failure gracefully by falling back to local deterministic analysis', async () => {
    const errorObj = Object.assign(new Error('Backend endpoint unavailable: 500 Internal Error'), { statusCode: 500, code: 'HTTP_500' });
    const spy = vi.spyOn(api, 'analyzeFinding').mockRejectedValueOnce(errorObj);

    render(<AiSecurityAnalyzerScreen />);

    // Trigger analysis
    const executeBtn = screen.getByRole('button', { name: /Analyze Code Security/i });
    fireEvent.click(executeBtn);

    // Analysis result continues to render through synthetic fallback
    expect(await screen.findByText(/Recommended Remediation/i)).toBeInTheDocument();

    spy.mockRestore();
  });
});

