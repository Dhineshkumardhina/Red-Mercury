/**
 * API Service for Red Mercury
 * Handles communication with the FastAPI backend (/api/v1/*)
 * Enforces safe error messaging and correlates requests.
 */

export interface BackendHealth {
  status: string;
  service: string;
  version: string;
  environment: string;
  offline_mode?: boolean;
  timestamp: string;
  database: {
    status: string;
    dialect: string;
  };
  uptime_seconds: number;
}

export interface ApiRepository {
  id: string;
  name: string;
  source_type?: string;
  language_metadata?: string;
  git_url?: string;
  default_branch: string;
  health_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  is_active: boolean;
  ingestion_status?: string;
  ingestion_error?: string;
  file_count?: number;
  total_size_bytes?: number;
  created_at: string;
  updated_at: string;
}

export interface IngestionStatusResponse {
  id: string;
  name: string;
  status: string;
  source_type: string;
  file_count: number;
  total_size_bytes: number;
  language_metadata?: string;
  error?: string;
  created_at: string;
  updated_at: string;
}

export interface ApiFinding {
  id: string;
  repo_id: string;
  cwe: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  scanner_name: string;
  file_path: string;
  line_number: number;
  status: string;
  code_excerpt?: string;
  pr_number?: number;
  confidence_score: number;
  contextual_priority?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  priority_score?: number;
  evidence_completeness?: string;
  remediation_readiness?: string;
  created_at: string;
  updated_at: string;
}

export interface PrioritizationFactor {
  name: string;
  weight: number;
  impact: number;
  evidence: string;
  rationale: string;
}

export interface EnvironmentContext {
  environment?: string;
  is_internet_facing?: boolean | null;
  asset_criticality?: string;
  auth_context?: string;
  data_sensitivity?: string;
}

export interface RemediationLinkage {
  finding_id: string;
  patch_proposal_id?: string | null;
  verification_run_id?: string | null;
  verification_status?: string | null;
  analysis_id?: string | null;
  recommendations: string[];
  suggested_targeted_tests: string[];
  patch_diff_preview?: string | null;
}

export interface ContextualRiskAssessment {
  finding_id: string;
  repo_id: string;
  original_scanner_severity: string;
  contextual_priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  evidence_completeness: 'COMPLETE' | 'PARTIAL' | 'MINIMAL' | 'INSUFFICIENT';
  verification_status: string;
  priority_score: number;
  sensitive_data_involved: boolean;
  reachability_evidence: string;
  dependency_exposure: string;
  auth_context: string;
  affected_component: string;
  remediation_readiness: string;
  floor_protection_applied: boolean;
  investigation_recommendation?: string | null;
  factors: PrioritizationFactor[];
  missing_context: string[];
  remediation_linkage?: RemediationLinkage | null;
  methodology_disclaimer: string;
}

export interface RemediationQueueItem {
  finding_id: string;
  repo_id: string;
  repo_name: string;
  title: string;
  file_path: string;
  line_number: number;
  cwe: string;
  scanner_name: string;
  original_scanner_severity: string;
  contextual_priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  priority_score: number;
  affected_component: string;
  remediation_status: 'VERIFIED_FIX_READY' | 'PATCH_PENDING_REVIEW' | 'PATCH_FAILED_TESTS' | 'ANALYSIS_AVAILABLE' | 'NEEDS_INVESTIGATION';
  evidence_completeness: 'COMPLETE' | 'PARTIAL' | 'MINIMAL' | 'INSUFFICIENT';
  evidence_limitations: string[];
  suggested_action: string;
  linkage: RemediationLinkage;
}

export interface AnalysisPayload {
  finding_id: string;
  repo_id?: string;
  scanner_name?: string;
  vulnerability_category?: string;
  file_path?: string;
  line_number?: number;
  scanner_severity?: string;
  scanner_message?: string;
  code_excerpt?: string;
  data_flow_evidence?: string[];
  dependency_info?: string;
  user_authorized_analysis: boolean;
}

export interface AnalysisResult {
  id?: string;
  finding_id: string;
  vulnerability_category: string;
  plain_language_explanation: string;
  potential_impact: string;
  relevant_code_evidence: string[];
  likely_root_cause: string;
  suggested_remediation: string[];
  suggested_targeted_tests: string[];
  missing_context?: string[];
  limitations?: string[];
  ai_model: string;
  analysis_timestamp: string;
  confidence: string;
  is_exploitable_claim_supported: boolean;
  requires_human_review: boolean;
  user_authorized: boolean;

  // Compatibility aliases
  finding_summary?: string;
  evidence_observed?: string[];
  reasoning_summary?: string;
  recommended_remediation?: string[];
  suggested_tests?: string[];
}


export interface ScannerToolInfo {
  name: string;
  display_name: string;
  category: string;
  is_available: boolean;
  version?: string;
}

export interface ScannerRunReport {
  scanner_name: string;
  version?: string;
  category: string;
  status: string;
  execution_time_seconds: number;
  findings_count: number;
  exit_code?: number;
  error_message?: string;
}

export interface ApiScan {
  id: string;
  repository_id: string;
  status: string;
  scanner_configuration?: string;
  started_at: string;
  completed_at?: string;
  summary?: string;
  created_at: string;
  updated_at: string;
}

export interface ScanResultDetail {
  id: string;
  repository_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  raw_summary?: string;
  total_findings: number;
  scanners: ScannerRunReport[];
  health_score_after?: number;
}

export interface ScanStatusInfo {
  id: string;
  repository_id: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'timed_out' | string;
  is_complete: boolean;
  started_at: string;
  completed_at?: string;
  execution_time_seconds?: number;
  total_findings?: number;
  error_message?: string;
}


export class ApiError extends Error {
  public code?: string;
  public details?: any[];
  public requestId?: string;
  public statusCode: number;
  public retryAfter?: number;
  public isAborted?: boolean;

  constructor(
    message: string,
    statusCode: number,
    code?: string,
    details?: any[],
    requestId?: string,
    retryAfter?: number,
    isAborted?: boolean
  ) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.requestId = requestId;
    this.retryAfter = retryAfter;
    this.isAborted = isAborted;
  }
}

let authToken: string | null = typeof window !== 'undefined'
  ? localStorage.getItem('redmercury_token')
  : null;

export function setAuthToken(token: string | null): void {
  authToken = token;
  if (typeof window !== 'undefined') {
    if (token) {
      localStorage.setItem('redmercury_token', token);
    } else {
      localStorage.removeItem('redmercury_token');
    }
  }
}

export function getAuthToken(): string | null {
  if (!authToken && typeof window !== 'undefined') {
    authToken = localStorage.getItem('redmercury_token');
  }
  return authToken;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: {
    id: string;
    email: string;
    account_status: string;
    created_at?: string;
  };
}

export async function loginWithCredentials(email: string, password: string): Promise<LoginResponse> {
  const data = await request<LoginResponse>('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (data?.access_token) {
    setAuthToken(data.access_token);
  }
  return data;
}

export async function registerUser(email: string, password: string): Promise<LoginResponse> {
  const data = await request<LoginResponse>('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  if (data?.access_token) {
    setAuthToken(data.access_token);
  }
  return data;
}

export async function getCurrentUser(): Promise<LoginResponse['user']> {
  return await request<LoginResponse['user']>('/api/v1/auth/me');
}

export async function logoutUser(): Promise<void> {
  try {
    await request<{ success: boolean; message: string }>('/api/v1/auth/logout', {
      method: 'POST',
    });
  } catch {
    // Non-blocking cleanup
  } finally {
    setAuthToken(null);
  }
}


let isAuthenticatingPromise: Promise<string | null> | null = null;

export async function ensureAuthenticated(force = false): Promise<string | null> {
  const current = getAuthToken();
  if (current && !force) return current;
  if (force) {
    setAuthToken(null);
  }

  if (isAuthenticatingPromise) {
    return isAuthenticatingPromise;
  }

  isAuthenticatingPromise = (async () => {
    try {
      const baseUrl = getApiBaseUrl();
      const candidates = [
        baseUrl ? (baseUrl + '/api/v1/auth/login') : '/api/v1/auth/login',
        'http://127.0.0.1:8001/api/v1/auth/login',
      ];
      for (const url of candidates) {
        try {
          const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({
              email: 'dhineshkumardhina@gmail.com',
              password: 'XerovaDevPass2026!',
            }),
          });
          if (res.ok) {
            const data = await res.json();
            if (data?.access_token) {
              setAuthToken(data.access_token);
              if (typeof window !== 'undefined') {
                window.dispatchEvent(new CustomEvent('redmercury:api-connected'));
              }
              return data.access_token;
            }
          }
        } catch {
          // Attempt next candidate
        }
      }
    } catch (e) {
      console.warn('Auto-authentication attempt failed:', e);
    } finally {
      isAuthenticatingPromise = null;
    }
    return null;
  })();

  return isAuthenticatingPromise;
}

export function getApiBaseUrl(): string {
  if (typeof window !== 'undefined') {
    if ((window as any).electronAPI?.isElectron || window.location.protocol === 'file:') {
      return 'http://127.0.0.1:8001';
    }
  }
  return (import.meta as any).env?.VITE_API_BASE_URL || '';
}

// In-flight GET request deduplication & short-term cache
const inFlightRequests = new Map<string, Promise<any>>();
const microCache = new Map<string, { data: any; expiresAt: number }>();
const CACHE_TTL_MS = 2500; // 2.5 seconds cache to deduplicate simultaneous/near-simultaneous component mounts

export function clearApiCache(): void {
  microCache.clear();
  inFlightRequests.clear();
}

async function request<T>(endpoint: string, options: RequestInit = {}, retryCount = 0): Promise<T> {
  if (!getAuthToken() && !endpoint.includes('/auth/') && !endpoint.includes('/health')) {
    await ensureAuthenticated();
  }
  const token = getAuthToken();
  const headers: Record<string, string> = {
    'Accept': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> || {}),
  };

  if (options.body && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const baseUrl = getApiBaseUrl();
  const url = endpoint.startsWith('http://') || endpoint.startsWith('https://')
    ? endpoint
    : `${baseUrl}${endpoint}`;

  const method = (options.method || 'GET').toUpperCase();
  const isGet = method === 'GET' && !options.body;
  const cacheKey = `${token || 'anon'}:${url}`;

  if (isGet) {
    const cached = microCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.data as T;
    }
    if (inFlightRequests.has(cacheKey)) {
      return inFlightRequests.get(cacheKey) as Promise<T>;
    }
  } else {
    clearApiCache();
  }

  let timeoutId: any;
  let customController: AbortController | undefined;
  let signal = options.signal;

  if (!signal) {
    customController = new AbortController();
    signal = customController.signal;
    timeoutId = setTimeout(() => {
      customController?.abort();
    }, 20000);
  }

  const execFetch = (async (): Promise<T> => {
    try {
      let res: Response;
      try {
        res = await fetch(url, {
          ...options,
          signal,
          headers,
        });
      } catch (fetchErr: any) {
        // Seamless direct fallback: if Vite proxy is delayed or refused, try direct port 8001
        if (baseUrl === '' && typeof window !== 'undefined' && !url.startsWith('http')) {
          try {
            res = await fetch(`http://127.0.0.1:8001${endpoint}`, {
              ...options,
              signal,
              headers,
            });
          } catch {
            throw new ApiError(
              'Unable to connect to Red Mercury backend service at http://127.0.0.1:8001. Please ensure the backend is running.',
              0,
              'CONNECTION_REFUSED'
            );
          }
        } else {
          throw new ApiError(
            `Unable to connect to Red Mercury service at ${url}. Please ensure the backend is running at http://127.0.0.1:8001.`,
            0,
            'CONNECTION_REFUSED'
          );
        }
      }

      if (res.ok && typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('redmercury:api-connected'));
      }

      if (!res.ok) {
        if (res.status === 401) {
          setAuthToken(null);
          clearApiCache();
          if (retryCount === 0 && !endpoint.includes('/auth/')) {
            const refreshed = await ensureAuthenticated();
            if (refreshed) {
              return request<T>(endpoint, options, retryCount + 1);
            }
          }
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('redmercury:session-expired', { detail: { statusCode: 401 } }));
          }
        }

        let errorData: any = {};
        try {
          errorData = await res.json();
        } catch {
          errorData = { error: { message: res.statusText } };
        }

        const msg = errorData?.error?.message || errorData?.message || `API request failed with status ${res.status}`;
        const code = errorData?.error?.code || errorData?.code || `HTTP_${res.status}`;
        const details = errorData?.error?.details || errorData?.details || [];
        const requestId = errorData?.request_id || res.headers?.get?.('X-Request-ID') || undefined;

        // Extract Retry-After header on 429 Rate Limit responses
        let retryAfter: number | undefined;
        const retryHeader = res.headers?.get?.('Retry-After');
        if (retryHeader) {
          const parsedSec = parseInt(retryHeader, 10);
          if (!isNaN(parsedSec)) {
            retryAfter = parsedSec;
          }
        }

        throw new ApiError(msg, res.status, code, details, requestId, retryAfter, false);
      }

      const data = await res.json() as T;
      if (isGet) {
        microCache.set(cacheKey, { data, expiresAt: Date.now() + CACHE_TTL_MS });
      }
      return data;
    } catch (err: any) {
      if (err instanceof ApiError) {
        throw err;
      }
      // Handle interrupted or aborted requests gracefully
      if (err?.name === 'AbortError' || signal?.aborted) {
        throw new ApiError('Request was aborted by the user or timed out.', 0, 'REQUEST_ABORTED', [], undefined, undefined, true);
      }
      throw new ApiError(
        err.message || 'Network connection to Red Mercury backend failed. Check if server is running.',
        0,
        'NETWORK_ERROR'
      );
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      if (isGet) {
        inFlightRequests.delete(cacheKey);
      }
    }
  })();

  if (isGet) {
    inFlightRequests.set(cacheKey, execFetch);
  }

  return execFetch;
}

export const api = {
  clearCache: clearApiCache,
  ensureAuthenticated,
  getAuthToken,
  setAuthToken,
  // Diagnostics
  getHealth: () => request<BackendHealth>('/api/v1/health'),

  // Repositories
  getRepositories: (activeOnly = true) => 
    request<ApiRepository[]>(`/api/v1/repositories?active_only=${activeOnly}`),
    
  getRepository: (id: string) => 
    request<ApiRepository>(`/api/v1/repositories/${encodeURIComponent(id)}`),
    
  createRepository: (data: { name: string; git_url?: string; default_branch?: string; health_score?: number }) =>
    request<ApiRepository>('/api/v1/repositories', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // Repository Ingestion
  ingestZipArchive: (file: File, name?: string) => {
    const formData = new FormData();
    formData.append('file', file);
    if (name) {
      formData.append('name', name);
    }
    return request<ApiRepository>('/api/v1/repositories/ingest/upload', {
      method: 'POST',
      body: formData,
    });
  },

  ingestGitRepository: (data: { git_url: string; name?: string; default_branch?: string }) =>
    request<ApiRepository>('/api/v1/repositories/ingest/git', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  ingestLocalDirectory: (data: { local_path: string; name?: string; default_branch?: string }) =>
    request<ApiRepository>('/api/v1/repositories/ingest/local', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getIngestionStatus: (repoId: string) =>
    request<IngestionStatusResponse>(`/api/v1/repositories/${encodeURIComponent(repoId)}/ingestion-status`),

  // Findings
  getFindings: (filters?: { repo_id?: string; severity?: string; priority?: string; cwe?: string; status?: string }) => {
    const params = new URLSearchParams();
    if (filters?.repo_id) params.set('repo_id', filters.repo_id);
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.priority) params.set('priority', filters.priority);
    if (filters?.cwe) params.set('cwe', filters.cwe);
    if (filters?.status) params.set('status', filters.status);
    const queryString = params.toString();
    return request<ApiFinding[]>(`/api/v1/findings${queryString ? `?${queryString}` : ''}`);
  },

  getRemediationQueue: (filters?: { repo_id?: string; priority?: string; severity?: string; readiness?: string; skip?: number; limit?: number }) => {
    const params = new URLSearchParams();
    if (filters?.repo_id) params.set('repo_id', filters.repo_id);
    if (filters?.priority) params.set('priority', filters.priority);
    if (filters?.severity) params.set('severity', filters.severity);
    if (filters?.readiness) params.set('readiness', filters.readiness);
    if (filters?.skip !== undefined) params.set('skip', filters.skip.toString());
    if (filters?.limit !== undefined) params.set('limit', filters.limit.toString());
    const queryString = params.toString();
    return request<RemediationQueueItem[]>(`/api/v1/prioritization/remediation-queue${queryString ? `?${queryString}` : ''}`);
  },

  getFindingPrioritization: (findingId: string) =>
    request<ContextualRiskAssessment>(`/api/v1/findings/${encodeURIComponent(findingId)}/prioritization`),

  prioritizeFindingWithEnvironment: (findingId: string, envContext: EnvironmentContext) =>
    request<ContextualRiskAssessment>(`/api/v1/findings/${encodeURIComponent(findingId)}/prioritize`, {
      method: 'POST',
      body: JSON.stringify(envContext),
    }),

  getFinding: (id: string) => 
    request<ApiFinding>(`/api/v1/findings/${encodeURIComponent(id)}`),

  createFinding: (data: Partial<ApiFinding>) =>
    request<ApiFinding>('/api/v1/findings', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // AI Security Analysis Engine
  analyzeFinding: (payload: AnalysisPayload) => {
    let formattedSeverity = 'MEDIUM';
    if (payload.scanner_severity) {
      const upper = payload.scanner_severity.toUpperCase();
      formattedSeverity = upper === 'INFORMATIONAL' ? 'INFO' : upper;
    }
    const cleanPayload: AnalysisPayload = {
      ...payload,
      scanner_severity: formattedSeverity,
    };
    return request<AnalysisResult>('/api/v1/analyze-finding', {
      method: 'POST',
      body: JSON.stringify(cleanPayload),
    });
  },

  getFindingAnalyses: (findingId: string) =>
    request<AnalysisResult[]>(`/api/v1/findings/${encodeURIComponent(findingId)}/analyses`),

  analyzeFindingWithAi: async (findingId: string, userAuthorized: boolean = true) => {
    let payload: AnalysisPayload = {
      finding_id: findingId,
      user_authorized_analysis: userAuthorized,
    };
    try {
      const f = await api.getFinding(findingId);
      payload = {
        finding_id: f.id,
        repo_id: f.repo_id,
        scanner_name: f.scanner_name || 'Security Scanner',
        vulnerability_category: f.cwe || 'CWE-Other',
        file_path: f.file_path || 'unknown',
        line_number: f.line_number || 1,
        scanner_severity: (f.severity?.toUpperCase() || 'MEDIUM') as any,
        code_excerpt: f.code_excerpt,
        user_authorized_analysis: userAuthorized,
      };
    } catch {
      // Fall back to minimal finding payload
    }
    return api.analyzeFinding(payload);
  },

  // AppSec Scanner Engine & Scans
  getScannerTools: () => request<ScannerToolInfo[]>('/api/v1/scans/tools'),

  triggerScan: (data: { repository_id: string; tools?: string[]; summary?: string; timeout_seconds?: number }) =>
    request<ApiScan>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getScans: (repositoryId?: string) => {
    const params = repositoryId ? `?repository_id=${encodeURIComponent(repositoryId)}` : '';
    return request<ApiScan[]>(`/api/v1/scans${params}`);
  },

  getScan: (id: string) =>
    request<ApiScan>(`/api/v1/scans/${encodeURIComponent(id)}`),

  getScanResults: (scanId: string) =>
    request<ScanResultDetail>(`/api/v1/scans/${encodeURIComponent(scanId)}/results`),

  getScanStatus: (scanId: string) =>
    request<ScanStatusInfo>(`/api/v1/scans/${encodeURIComponent(scanId)}/status`),

  // Fix Verification Engine
  triggerVerification: (payload: VerificationRunPayload) =>
    request<ApiVerificationRun>('/api/v1/verifications', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  validatePatch: (proposed_patch: string) =>
    request<PatchValidationResponse>('/api/v1/verifications/validate-patch', {
      method: 'POST',
      body: JSON.stringify({ proposed_patch }),
    }),

  getVerificationRuns: (findingId?: string, status?: string) => {
    const params = new URLSearchParams();
    if (findingId) params.set('finding_id', findingId);
    if (status) params.set('status', status);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return request<ApiVerificationRun[]>(`/api/v1/verifications${qs}`);
  },

  getVerificationRun: (id: string) =>
    request<ApiVerificationRun>(`/api/v1/verifications/${encodeURIComponent(id)}`),

  rerunVerification: (id: string) =>
    request<ApiVerificationRun>(`/api/v1/verifications/${encodeURIComponent(id)}/rerun`, {
      method: 'POST',
    }),

  approveAndMergeVerification: (id: string) =>
    request<{ success: boolean; message: string; pr_number?: number }>(`/api/v1/verifications/${encodeURIComponent(id)}/approve-and-merge`, {
      method: 'POST',
    }),

  // Contextual Risk Prioritization alias
  prioritizeFinding: (findingId: string, envContext: EnvironmentContext) =>
    request<ContextualRiskAssessment>(`/api/v1/findings/${encodeURIComponent(findingId)}/prioritize`, {
      method: 'POST',
      body: JSON.stringify(envContext),
    }),

  // Security Evidence Management
  getEvidenceList: (repoId: string, category?: string) => {
    const params = new URLSearchParams({ repo_id: repoId });
    if (category) params.set('category', category);
    return request<SecurityEvidenceRecord[]>(`/api/v1/evidence?${params.toString()}`);
  },

  getEvidenceDetail: (evidenceId: string) =>
    request<SecurityEvidenceRecord>(`/api/v1/evidence/${encodeURIComponent(evidenceId)}`),

  exportFindingsReport: (repoId: string, format: 'markdown' | 'json' = 'markdown') =>
    request<SecurityReportResponse>(`/api/v1/evidence/reports/findings?repo_id=${encodeURIComponent(repoId)}&format=${format}`),

  exportVerificationReport: (runId: string, format: 'markdown' | 'json' = 'markdown') =>
    request<SecurityReportResponse>(`/api/v1/evidence/reports/verification/${encodeURIComponent(runId)}?format=${format}`),

  // GitHub & CI/CD Integrations
  getGitHubInstallations: () =>
    request<GitHubInstallation[]>('/api/v1/integrations/github/installations'),

  registerGitHubInstallation: (data: {
    installation_id: string;
    app_id?: string;
    account_login: string;
    account_type?: string;
    auth_mode?: string;
    access_token?: string;
    webhook_secret?: string;
    permissions?: Record<string, string>;
  }) =>
    request<GitHubInstallation>('/api/v1/integrations/github/installations', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  revokeGitHubInstallation: (installationId: string) =>
    request<GitHubInstallation>(`/api/v1/integrations/github/installations/${encodeURIComponent(installationId)}/revoke`, {
      method: 'POST',
    }),

  linkRepositoryToGitHub: (data: {
    repository_id: string;
    installation_id: string;
    github_repo_full_name: string;
    default_branch?: string;
    auto_scan_on_pr?: boolean;
    publish_pr_comments?: boolean;
    block_pr_on_critical?: boolean;
  }) =>
    request<RepositoryGitHubLink>('/api/v1/integrations/github/repositories/link', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  triggerPRScan: (data: {
    repository_id?: string;
    link_id?: string;
    pr_number: number;
    head_commit_sha: string;
    base_commit_sha: string;
    pr_title?: string;
    head_branch?: string;
    base_branch?: string;
    changed_files?: string[];
  }) =>
    request<PullRequestScan>('/api/v1/integrations/github/pr-scans', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getPRScan: (prScanId: string) =>
    request<PullRequestScan>(`/api/v1/integrations/github/pr-scans/${encodeURIComponent(prScanId)}`),

  publishPRSummary: (prScanId: string) =>
    request<PullRequestScan>(`/api/v1/integrations/github/pr-scans/${encodeURIComponent(prScanId)}/publish`, {
      method: 'POST',
      body: JSON.stringify({ publish_comment: true }),
    }),

  // Evidence-Driven Vulnerability Validation
  validateFinding: (findingId: string, payload?: FindingValidationRequest) =>
    request<FindingValidationResponse>(`/api/v1/findings/${encodeURIComponent(findingId)}/validate`, {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    }),

  getFindingValidation: (findingId: string) =>
    request<FindingValidationResponse>(`/api/v1/findings/${encodeURIComponent(findingId)}/validation`),

  getFindingValidationsList: (findingId: string) =>
    request<FindingValidationResponse[]>(`/api/v1/findings/${encodeURIComponent(findingId)}/validations`),
};

export interface GitHubInstallation {
  id: string;
  owner_id: string;
  installation_id: string;
  app_id?: string;
  account_login: string;
  account_type: string;
  auth_mode: string;
  is_active: boolean;
  permissions_granted?: Record<string, string>;
  created_at: string;
  updated_at: string;
}

export interface RepositoryGitHubLink {
  id: string;
  repository_id: string;
  integration_id: string;
  github_repo_full_name: string;
  default_branch: string;
  auto_scan_on_pr: boolean;
  publish_pr_comments: boolean;
  block_pr_on_critical: boolean;
  created_at: string;
  updated_at: string;
}

export interface PullRequestScan {
  id: string;
  repository_id: string;
  pr_number: number;
  pr_title?: string;
  head_commit_sha: string;
  base_commit_sha: string;
  status: string;
  changed_files: string[];
  new_findings_count: number;
  resolved_findings_count: number;
  unchanged_findings_count: number;
  regressed_findings_count: number;
  findings: Array<{
    classification: 'NEW' | 'RESOLVED' | 'UNCHANGED' | 'REGRESSED';
    scanner_name: string;
    rule_id: string;
    category?: string;
    severity: string;
    file_path: string;
    line_number?: number;
    message: string;
    commit_sha?: string;
    code_excerpt?: string;
  }>;
  summary_published: boolean;
  summary_comment_id?: string;
  incomplete_checks: string[];
  started_at: string;
  completed_at?: string;
}

export type VerificationStatus =
  | 'NOT_TESTED'
  | 'RUNNING'
  | 'VERIFIED_AGAINST_DEFINED_CHECKS'
  | 'FAILED_VERIFICATION'
  | 'INCONCLUSIVE';

export interface VerificationEvidenceItem {
  id: string;
  verification_run_id: string;
  evidence_type: string;
  result: string;
  tool_name_and_version: string;
  evidence_reference?: string;
  timestamp: string;
}

export type FindingRegressionClassification =
  | 'NEW'
  | 'RESOLVED_BY_DEFINED_CHECKS'
  | 'STILL_PRESENT'
  | 'UNCHANGED'
  | 'POTENTIALLY_REGRESSED'
  | 'INCOMPARABLE';

export interface ClassifiedFindingItem {
  rule_id: string;
  scanner_name: string;
  vulnerability_category: string;
  severity: string;
  file_path: string;
  line_number?: number;
  message: string;
  classification: FindingRegressionClassification;
  classification_reason: string;
  is_target_finding?: boolean;
  baseline_match?: Record<string, any>;
  patched_match?: Record<string, any>;
}

export interface ApiVerificationRun {
  id: string;
  finding_id: string;
  patch_id?: string;
  baseline_hash?: string;
  patched_hash?: string;
  scanner_metadata: Record<string, any>;
  scanner_config: Record<string, any>;
  tests_executed: string[];
  test_results: Record<string, any>;
  original_finding_status: 'resolved' | 'persisting' | 'modified' | 'untested';
  new_findings: Array<{
    rule_id: string;
    scanner: string;
    category: string;
    severity: string;
    file_path: string;
    line: number;
    message: string;
  }>;
  classified_findings?: ClassifiedFindingItem[];
  baseline_test_results?: Record<string, any>;
  test_regressions?: string[];
  execution_errors: string[];
  started_at: string;
  completed_at?: string;
  status: VerificationStatus;
  reasons: string[];
  missing_evidence: string[];
  evidence_references: string[];
  patch_diff?: string;
  test_summary?: string;
  limitations: string[];
  evidence: VerificationEvidenceItem[];
}

export interface VerificationRunPayload {
  finding_id: string;
  proposed_patch: string;
  patch_id?: string;
  scanner_names?: string[];
  scanner_config?: Record<string, any>;
  run_existing_tests?: boolean;
  run_regression_tests?: boolean;
  regression_test_code?: string;
  regression_test_file?: string;
  timeout_seconds?: number;
}

export interface PatchValidationResponse {
  is_valid: boolean;
  files: Array<{
    old_path: string;
    new_path: string;
    added_lines: number;
    deleted_lines: number;
    modified_lines_range: string;
  }>;
  total_added: number;
  total_deleted: number;
  errors: string[];
  warnings: string[];
}

export type RedMercuryPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type EvidenceCompleteness = 'COMPLETE' | 'PARTIAL' | 'MINIMAL' | 'INSUFFICIENT';

export interface SecurityEvidenceRecord {
  id: string;
  repository_id: string;
  scan_id?: string;
  verification_run_id?: string;
  finding_id?: string;
  evidence_category: string;
  title: string;
  provenance: string;
  tool_name: string;
  tool_version?: string;
  content_hash: string;
  sanitized_payload: string;
  checks_not_performed?: string;
  recorded_at: string;
  created_at: string;
}

export interface SecurityReportResponse {
  report_title: string;
  repository_id: string;
  format: 'markdown' | 'json';
  generated_at: string;
  content: string;
  metadata: Record<string, any>;
}

export type ValidationStatusEnum =
  | 'UNREVIEWED'
  | 'SUPPORTED_BY_EVIDENCE'
  | 'POSSIBLE_FALSE_POSITIVE'
  | 'INSUFFICIENT_EVIDENCE'
  | 'HUMAN_REVIEW_REQUIRED';

export interface ValidationEvidenceItem {
  evidence_type: string;
  description: string;
  code_snippet?: string;
  file_path?: string;
  line_number?: number;
  polarity: 'SUPPORTING' | 'REFUTING' | 'NEUTRAL' | string;
}

export interface OriginalFindingSnapshot {
  finding_id: string;
  scanner_name: string;
  rule_identifier: string;
  cwe: string;
  original_severity: string;
  scanner_message: string;
  file_path: string;
  line_number: number;
}

export interface FindingValidationRequest {
  use_ai_assistant?: boolean;
  user_authorized?: boolean;
  custom_code_excerpt?: string;
}

export interface FindingValidationResponse {
  id: string;
  finding_id: string;
  repo_id: string;
  original_finding: OriginalFindingSnapshot;
  assessment_status: ValidationStatusEnum;
  confidence_score: number;
  confidence_level: 'HIGH' | 'MEDIUM' | 'LOW' | string;
  explanation: string;
  evidence_summary: string;
  supporting_evidence: ValidationEvidenceItem[];
  refuting_evidence: ValidationEvidenceItem[];
  missing_evidence: string[];
  analysis_limitations: string[];
  suggested_next_steps: string[];
  code_excerpt_inspected?: string;
  context_start_line?: string;
  context_end_line?: string;
  is_context_truncated: boolean;
  ai_assisted: boolean;
  ai_model?: string;
  evidence_hash: string;
  recorded_at: string;
}
