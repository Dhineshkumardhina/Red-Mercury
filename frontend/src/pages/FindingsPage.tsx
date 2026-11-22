import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Shield,
  RotateCw,
  Play,
  CheckCircle2,
  Bug,
  Key,
  Search,
  X,
  LayoutList,
  Table as TableIcon,
  FolderGit2,
  ChevronUp,
  Eye,
  ChevronRight,
  ArrowRight,
  Code2,
  Loader2,
  AlertCircle,
  FileCode,
} from 'lucide-react';
import { api, ApiFinding, ApiRepository } from '../services/api';
import { SecurityFinding, VerificationItem } from '../types';
import {
  SeverityBadge,
  LoadingState,
  EmptyState,
} from '../components/common';
import { DiffModal } from '../components/modals/DiffModal';

export const FindingsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [liveFindings, setLiveFindings] = useState<ApiFinding[]>([]);
  const [repositories, setRepositories] = useState<ApiRepository[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState(searchParams.get('cwe') || searchParams.get('q') || '');
  const [selectedCategory, setSelectedCategory] = useState<'all' | 'vulnerabilities' | 'secrets'>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>(searchParams.get('severity') || 'all');
  const [selectedRepo, setSelectedRepo] = useState<string>(searchParams.get('repo') || 'all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);

  useEffect(() => {
    const cweParam = searchParams.get('cwe') || searchParams.get('q');
    if (cweParam !== null) {
      setSearchQuery(cweParam);
    }
    const sevParam = searchParams.get('severity');
    if (sevParam !== null) {
      setSelectedSeverity(sevParam);
    }
    const repoParam = searchParams.get('repo');
    if (repoParam !== null) {
      setSelectedRepo(repoParam);
    }
  }, [searchParams]);

  // Diff modal
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);

  const loadData = async (refresh = false) => {
    if (refresh) {
      api.clearCache();
      setIsRefreshing(true);
    } else {
      setIsLoading(true);
    }
    setApiError(null);

    try {
      const [findingsRes, reposRes] = await Promise.all([
        api.getFindings(),
        api.getRepositories(true).catch(() => [] as ApiRepository[]),
      ]);
      setLiveFindings(findingsRes || []);
      setRepositories(reposRes || []);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('redmercury:api-connected'));
      }
    } catch (err: any) {
      const msg = err?.message || '';
      if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('CONNECTION_REFUSED')) {
        setApiError('Unable to connect to Red Mercury backend service at http://127.0.0.1:8001. Please ensure the backend server is running.');
      } else {
        setApiError(err.message || 'Unable to retrieve findings. Please check backend connection.');
      }
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Update URL params when severity changes
  const handleSeverityChange = (newSev: string) => {
    setSelectedSeverity(newSev);
    const newParams = new URLSearchParams(searchParams);
    if (newSev === 'all') {
      newParams.delete('severity');
    } else {
      newParams.set('severity', newSev);
    }
    setSearchParams(newParams, { replace: true });
  };

  // Convert raw findings to enriched items
  const enrichedFindings: SecurityFinding[] = useMemo(() => {
    return liveFindings.map(lf => {
      const isSecret = lf.cwe?.includes('798') ||
        lf.scanner_name?.toLowerCase().includes('secret') ||
        lf.scanner_name?.toLowerCase().includes('gitleaks');

      const isFixReady = lf.remediation_readiness === 'VERIFIED_FIX_READY' || !!lf.pr_number;

      return {
        id: lf.id,
        cve: lf.id,
        cwe: lf.cwe || 'CWE-Unknown',
        cweName: lf.title,
        title: lf.title,
        severity: lf.severity.toLowerCase() as any,
        cvss: lf.severity === 'CRITICAL' ? 9.8 : lf.severity === 'HIGH' ? 8.2 : lf.severity === 'MEDIUM' ? 5.5 : 3.2,
        repo: lf.repo_id,
        branch: 'main',
        filePath: lf.file_path,
        line: lf.line_number,
        engine: lf.scanner_name,
        ruleId: lf.cwe || 'security.rule',
        description: lf.title,
        taintTrace: {
          source: 'Untrusted user input vector',
          flow: ['Data propagation via handler parameters', 'Unsanitized input sink'],
          sink: 'Execution / Storage sink boundary',
        },
        remediationStatus: isFixReady ? 'verified_patch' : 'needs_patch',
        prNumber: lf.pr_number,
        contextualPriority: (lf.contextual_priority?.toLowerCase() || lf.severity.toLowerCase()) as any,
        priorityScore: lf.priority_score ?? (lf.severity === 'CRITICAL' ? 85 : lf.severity === 'HIGH' ? 65 : 45),
        evidenceCompleteness: lf.evidence_completeness || 'PARTIAL',
        remediationReadiness: lf.remediation_readiness || (lf.pr_number ? 'VERIFIED_FIX_READY' : 'NEEDS_INVESTIGATION'),
        diff: lf.pr_number ? {
          filePath: lf.file_path,
          oldCode: [{ line: lf.line_number, text: `// original vulnerable statement in ${lf.file_path}` }],
          newCode: [{ line: lf.line_number, text: `// sanitized safe statement (PR #${lf.pr_number})` }],
          ruleId: lf.cwe || 'security.fix',
        } : undefined,
      };
    });
  }, [liveFindings]);

  // Overall Statistics for KPI Cards
  const stats = useMemo(() => {
    const total = enrichedFindings.length;
    const critical = enrichedFindings.filter(f => f.severity === 'critical').length;
    const high = enrichedFindings.filter(f => f.severity === 'high').length;
    const mediumLow = enrichedFindings.filter(f => f.severity === 'medium' || f.severity === 'low').length;
    const secrets = enrichedFindings.filter(f => f.cwe.includes('798') || f.engine.toLowerCase().includes('secret') || f.engine.toLowerCase().includes('gitleaks')).length;
    const vulnerabilities = total - secrets;
    const fixesReady = enrichedFindings.filter(f => f.remediationReadiness === 'VERIFIED_FIX_READY' || f.remediationStatus === 'verified_patch').length;

    return { total, critical, high, mediumLow, secrets, vulnerabilities, fixesReady };
  }, [enrichedFindings]);

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    return enrichedFindings.filter(f => {
      const isSecret = f.cwe.includes('798') || f.engine.toLowerCase().includes('secret') || f.engine.toLowerCase().includes('gitleaks');

      // Category filter
      if (selectedCategory === 'secrets' && !isSecret) return false;
      if (selectedCategory === 'vulnerabilities' && isSecret) return false;

      // Severity filter
      if (selectedSeverity !== 'all' && f.severity !== selectedSeverity) return false;

      // Repository filter
      if (selectedRepo !== 'all' && f.repo.toLowerCase() !== selectedRepo.toLowerCase()) return false;

      // Status filter
      if (selectedStatus === 'fix_ready' && f.remediationReadiness !== 'VERIFIED_FIX_READY' && f.remediationStatus !== 'verified_patch') return false;
      if (selectedStatus === 'patch_proposed' && f.remediationReadiness !== 'PATCH_PENDING_REVIEW') return false;
      if (selectedStatus === 'needs_review' && (f.remediationReadiness === 'VERIFIED_FIX_READY' || f.remediationStatus === 'verified_patch')) return false;

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesCwe = f.cwe.toLowerCase().includes(q);
        const matchesPath = f.filePath.toLowerCase().includes(q);
        const matchesRepo = f.repo.toLowerCase().includes(q);
        const matchesEngine = f.engine.toLowerCase().includes(q);
        const matchesId = f.id.toLowerCase().includes(q);
        if (!matchesTitle && !matchesCwe && !matchesPath && !matchesRepo && !matchesEngine && !matchesId) {
          return false;
        }
      }

      return true;
    });
  }, [enrichedFindings, selectedCategory, selectedSeverity, selectedRepo, selectedStatus, searchQuery]);

  const hasActiveFilters = selectedCategory !== 'all' ||
    selectedSeverity !== 'all' ||
    selectedRepo !== 'all' ||
    selectedStatus !== 'all' ||
    searchQuery.trim() !== '';

  const handleResetFilters = () => {
    setSelectedCategory('all');
    handleSeverityChange('all');
    setSelectedRepo('all');
    setSelectedStatus('all');
    setSearchQuery('');
  };

  const handleOpenDiff = (finding: SecurityFinding, e: React.MouseEvent) => {
    e.stopPropagation();
    if (finding.diff) {
      setActiveDiffItem({
        id: finding.id,
        repo: finding.repo,
        branch: finding.branch,
        gitHash: 'HEAD',
        engine: finding.engine,
        target: 'Source Code',
        findingsCount: {},
        status: 'verified',
        message: finding.title,
        executionTime: '0.1s',
        timestamp: 'Just now',
        diff: finding.diff,
      });
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Page Header */}
      <div className="px-6 lg:px-8 py-5 bg-white border-b border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Security Findings
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-xs font-medium border border-slate-200">
                {stats.total} Total
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Active security findings, vulnerability detections, and verified patches across monitored repositories.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={() => loadData(true)}
              disabled={isRefreshing || isLoading}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              title="Refresh findings from backend"
            >
              <RotateCw className={`w-3.5 h-3.5 text-slate-500 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>{isRefreshing ? 'Refreshing...' : 'Refresh'}</span>
            </button>

            <button
              type="button"
              onClick={() => navigate('/repositories')}
              className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Scan Repository</span>
            </button>
          </div>
        </div>

        {/* Interactive KPI Summary Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5 mt-5">
          {/* Card: Total */}
          <button
            type="button"
            onClick={() => {
              setSelectedSeverity('all');
              setSelectedStatus('all');
            }}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
              selectedSeverity === 'all' && selectedStatus === 'all'
                ? 'bg-slate-50 border-slate-400 shadow-2xs ring-1 ring-slate-400'
                : 'bg-white border-slate-200/80 hover:border-slate-300'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-slate-500 mb-1">
              <span className="font-medium">All Findings</span>
              <Shield className="w-4 h-4 text-slate-400" />
            </div>
            <div className="text-2xl font-semibold text-slate-900">{stats.total}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Across monitored repositories</div>
          </button>

          {/* Card: Critical */}
          <button
            type="button"
            onClick={() => handleSeverityChange('critical')}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
              selectedSeverity === 'critical'
                ? 'bg-rose-50/60 border-rose-400 shadow-2xs ring-1 ring-rose-400'
                : 'bg-white border-slate-200/80 hover:border-rose-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-rose-600 mb-1 font-medium">
              <span>Critical</span>
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            </div>
            <div className="text-2xl font-semibold text-rose-600">{stats.critical}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Immediate action required</div>
          </button>

          {/* Card: High */}
          <button
            type="button"
            onClick={() => handleSeverityChange('high')}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
              selectedSeverity === 'high'
                ? 'bg-amber-50/60 border-amber-400 shadow-2xs ring-1 ring-amber-400'
                : 'bg-white border-slate-200/80 hover:border-amber-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-amber-600 mb-1 font-medium">
              <span>High Risk</span>
              <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            </div>
            <div className="text-2xl font-semibold text-amber-600">{stats.high}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">High priority remediation</div>
          </button>

          {/* Card: Medium & Low */}
          <button
            type="button"
            onClick={() => handleSeverityChange('medium')}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
              selectedSeverity === 'medium'
                ? 'bg-blue-50/60 border-blue-400 shadow-2xs ring-1 ring-blue-400'
                : 'bg-white border-slate-200/80 hover:border-blue-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-blue-600 mb-1 font-medium">
              <span>Medium / Low</span>
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
            </div>
            <div className="text-2xl font-semibold text-slate-800">{stats.mediumLow}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Standard triage</div>
          </button>

          {/* Card: Fix Ready */}
          <button
            type="button"
            onClick={() => setSelectedStatus(selectedStatus === 'fix_ready' ? 'all' : 'fix_ready')}
            className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer col-span-2 sm:col-span-1 ${
              selectedStatus === 'fix_ready'
                ? 'bg-emerald-50/60 border-emerald-400 shadow-2xs ring-1 ring-emerald-400'
                : 'bg-white border-slate-200/80 hover:border-emerald-200'
            }`}
          >
            <div className="flex items-center justify-between text-xs text-emerald-700 mb-1 font-medium">
              <span>Fix Ready</span>
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            </div>
            <div className="text-2xl font-semibold text-emerald-700">{stats.fixesReady}</div>
            <div className="text-[11px] text-slate-400 mt-0.5">Verified fixes ready</div>
          </button>
        </div>
      </div>

      {/* Category Pills & Filter Toolbar */}
      <div className="px-6 lg:px-8 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Category Segment Control */}
        <div className="inline-flex p-0.5 rounded-lg bg-slate-200/70 border border-slate-200 self-start">
          <button
            type="button"
            onClick={() => setSelectedCategory('all')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer ${
              selectedCategory === 'all'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            All ({stats.total})
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('vulnerabilities')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              selectedCategory === 'vulnerabilities'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Bug className="w-3.5 h-3.5 text-amber-500" />
            <span>Vulnerabilities ({stats.vulnerabilities})</span>
          </button>
          <button
            type="button"
            onClick={() => setSelectedCategory('secrets')}
            className={`px-3 py-1 rounded-md text-xs font-medium transition-colors cursor-pointer flex items-center gap-1.5 ${
              selectedCategory === 'secrets'
                ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <Key className="w-3.5 h-3.5 text-rose-500" />
            <span>Secrets ({stats.secrets})</span>
          </button>
        </div>

        {/* Filter Dropdowns and Search */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Search Box */}
          <div className="relative min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search title, CWE, path..."
              className="w-full pl-8 pr-7 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-800 placeholder:text-slate-400 focus:outline-hidden focus:border-slate-400 shadow-2xs"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Severity Dropdown */}
          <select
            value={selectedSeverity}
            onChange={e => handleSeverityChange(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-700 font-medium focus:outline-hidden focus:border-slate-400 shadow-2xs cursor-pointer"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Repository Dropdown */}
          <select
            value={selectedRepo}
            onChange={e => setSelectedRepo(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-700 font-medium focus:outline-hidden focus:border-slate-400 shadow-2xs cursor-pointer max-w-[160px] truncate"
          >
            <option value="all">All Repositories</option>
            {repositories.map(repo => (
              <option key={repo.id} value={repo.id}>
                {repo.name}
              </option>
            ))}
          </select>

          {/* Status Dropdown */}
          <select
            value={selectedStatus}
            onChange={e => setSelectedStatus(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs text-slate-700 font-medium focus:outline-hidden focus:border-slate-400 shadow-2xs cursor-pointer"
          >
            <option value="all">All Fix Statuses</option>
            <option value="fix_ready">Verified Fix Ready</option>
            <option value="patch_proposed">Patch Proposed</option>
            <option value="needs_review">Needs Review</option>
          </select>

          {/* Reset Button */}
          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleResetFilters}
              className="px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:text-slate-900 border border-slate-200 rounded-lg bg-white hover:bg-slate-50 transition-colors cursor-pointer shadow-2xs"
            >
              Reset
            </button>
          )}

          {/* View Toggle */}
          <div className="hidden sm:inline-flex p-0.5 rounded-lg bg-slate-200/70 border border-slate-200 ml-1">
            <button
              type="button"
              onClick={() => setViewMode('cards')}
              className={`p-1.5 rounded-md text-xs transition-colors cursor-pointer ${
                viewMode === 'cards' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
              title="Card view"
            >
              <LayoutList className="w-3.5 h-3.5 block" />
            </button>
            <button
              type="button"
              onClick={() => setViewMode('table')}
              className={`p-1.5 rounded-md text-xs transition-colors cursor-pointer ${
                viewMode === 'table' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
              title="Compact table view"
            >
              <TableIcon className="w-3.5 h-3.5 block" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="px-6 lg:px-8 py-5">
        {/* Results Count Banner */}
        <div className="flex items-center justify-between text-xs text-slate-500 mb-3">
          <span>
            Showing <strong className="text-slate-800">{filteredFindings.length}</strong> of{' '}
            <strong className="text-slate-800">{stats.total}</strong> findings
          </span>
          {hasActiveFilters && (
            <span className="text-slate-400">
              Filtered view active •{' '}
              <button
                type="button"
                onClick={handleResetFilters}
                className="text-blue-600 hover:underline cursor-pointer"
              >
                Clear all
              </button>
            </span>
          )}
        </div>

        {/* Loading State */}
        {isLoading && <LoadingState message="Retrieving security findings from database..." />}

        {/* Error State */}
        {apiError && !isLoading && (
          <div className="mb-4 p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-center justify-between shadow-2xs">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
              <span>{apiError}</span>
            </div>
            <button
              type="button"
              disabled={isRefreshing}
              onClick={() => loadData(true)}
              className="px-3 py-1 bg-white border border-rose-300 rounded text-rose-800 font-semibold hover:bg-rose-100 transition-colors cursor-pointer flex items-center gap-1.5 disabled:opacity-50"
            >
              {isRefreshing && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              <span>{isRefreshing ? 'Reconnecting...' : 'Retry'}</span>
            </button>
          </div>
        )}

        {/* Empty State */}
        {!isLoading && !apiError && filteredFindings.length === 0 && (
          <EmptyState
            icon="verified"
            title={stats.total === 0 ? 'No security findings found' : 'No findings match your filters'}
            description={
              stats.total === 0
                ? 'Your monitored repositories are completely clean. Run a new scan from the Repositories section to check for newly introduced vulnerabilities.'
                : 'Try adjusting your search query, severity, repository, or fix readiness filters to locate findings.'
            }
            actionLabel={stats.total === 0 ? 'Go to Repositories' : 'Reset Filters'}
            onAction={stats.total === 0 ? () => navigate('/repositories') : handleResetFilters}
          />
        )}

        {/* Findings List - Card View */}
        {!isLoading && filteredFindings.length > 0 && viewMode === 'cards' && (
          <div className="space-y-3">
            {filteredFindings.map(finding => {
              const isExpanded = expandedFindingId === finding.id;
              const isFixReady = finding.remediationReadiness === 'VERIFIED_FIX_READY' || finding.remediationStatus === 'verified_patch';
              const isPatchProposed = finding.remediationReadiness === 'PATCH_PENDING_REVIEW';
              const isSecret = finding.cwe.includes('798') || finding.engine.toLowerCase().includes('secret') || finding.engine.toLowerCase().includes('gitleaks');

              return (
                <div
                  key={finding.id}
                  className={`bg-white border rounded-xl transition-all shadow-2xs hover:shadow-xs ${
                    isExpanded ? 'border-slate-400 ring-1 ring-slate-300' : 'border-slate-200/80 hover:border-slate-300'
                  }`}
                >
                  {/* Card Header Row */}
                  <div
                    onClick={() => navigate(`/findings/${finding.id}`)}
                    className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer group"
                  >
                    {/* Left: Severity & Finding Info */}
                    <div className="flex items-start gap-3 flex-1 min-w-0">
                      <div className="shrink-0 mt-0.5">
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </div>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="font-semibold text-slate-900 text-sm group-hover:text-blue-600 transition-colors">
                            {finding.title}
                          </span>
                          <span className="px-1.5 py-0.2 rounded text-[11px] font-medium bg-slate-100 text-slate-600 border border-slate-200">
                            {finding.cwe}
                          </span>
                          {isSecret && (
                            <span className="px-1.5 py-0.2 rounded text-[10px] font-medium bg-rose-50 text-rose-700 border border-rose-200">
                              Secret
                            </span>
                          )}
                          <span className="px-1.5 py-0.2 rounded text-[11px] text-slate-500 bg-slate-50 border border-slate-200">
                            {finding.engine}
                          </span>
                        </div>

                        {/* Location Details */}
                        <div className="flex items-center gap-2 text-xs text-slate-500 flex-wrap">
                          <span className="flex items-center gap-1 font-medium text-slate-700">
                            <FolderGit2 className="w-3.5 h-3.5 text-slate-400" />
                            {finding.repo}
                          </span>
                          <span>•</span>
                          <span className="inline-flex items-center gap-1 font-mono text-[11px] text-slate-600 truncate max-w-md">
                            <FileCode className="w-3.5 h-3.5 text-slate-400" />
                            {finding.filePath}:{finding.line}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Right: Status & Actions */}
                    <div className="flex items-center gap-2.5 shrink-0 self-end md:self-center" onClick={e => e.stopPropagation()}>
                      {/* Fix Status Pill */}
                      {isFixReady ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                          <span>Fix Ready</span>
                        </span>
                      ) : isPatchProposed ? (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700 border border-blue-200">
                          <Code2 className="w-3 h-3 text-blue-600" />
                          <span>Patch Proposed</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-600 border border-slate-200">
                          <Search className="w-3 h-3 text-slate-400" />
                          <span>Needs Review</span>
                        </span>
                      )}

                      {/* Quick Expand Toggle */}
                      <button
                        type="button"
                        onClick={() => setExpandedFindingId(isExpanded ? null : finding.id)}
                        className="px-2.5 py-1 rounded-lg border border-slate-200 text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors flex items-center gap-1 cursor-pointer"
                        title={isExpanded ? 'Collapse preview' : 'Quick preview'}
                      >
                        {isExpanded ? (
                          <ChevronUp className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                        <span className="hidden sm:inline">{isExpanded ? 'Less' : 'Preview'}</span>
                      </button>

                      {/* Run Fix Verification Button */}
                      <button
                        type="button"
                        onClick={e => {
                          e.stopPropagation();
                          navigate(`/verification?finding_id=${finding.id}`);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 text-white text-xs font-medium hover:bg-slate-800 transition-colors flex items-center gap-1 cursor-pointer shadow-2xs"
                        title="Verify fix in isolated sandbox"
                      >
                        <Play className="w-3 h-3 fill-current" />
                        <span>Verify Fix</span>
                      </button>

                      {/* View Diff Button (if diff exists) */}
                      {finding.diff && (
                        <button
                          type="button"
                          onClick={e => handleOpenDiff(finding, e)}
                          className="px-2.5 py-1 rounded-lg border border-slate-200 text-xs font-medium text-blue-600 hover:bg-blue-50 transition-colors cursor-pointer"
                        >
                          Diff
                        </button>
                      )}

                      {/* Direct Link to Detail */}
                      <button
                        type="button"
                        onClick={() => navigate(`/findings/${finding.id}`)}
                        className="p-1 rounded-lg text-slate-400 hover:text-slate-800 hover:bg-slate-100 transition-colors cursor-pointer"
                        title="View complete analysis & verification"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Expanded Quick Inspection Drawer */}
                  {isExpanded && (
                    <div className="px-4 py-3.5 bg-slate-50/70 border-t border-slate-200/80 rounded-b-xl text-xs space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200/80">
                          <span className="text-[10px] text-slate-500 uppercase font-semibold block">Risk Score</span>
                          <span className="font-semibold text-slate-900 text-sm">{finding.priorityScore?.toFixed(0)}/100</span>
                          <span className="text-[10px] text-slate-500 block mt-0.5">Contextual priority weight</span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200/80">
                          <span className="text-[10px] text-slate-500 uppercase font-semibold block">Scanner Rule</span>
                          <span className="font-mono text-slate-800 text-[11px] truncate block">{finding.ruleId}</span>
                          <span className="text-[10px] text-slate-500 block mt-0.5">AST pattern match</span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200/80">
                          <span className="text-[10px] text-slate-500 uppercase font-semibold block">Remediation Status</span>
                          <span className="font-medium text-slate-800 text-xs block">
                            {isFixReady ? 'Verified patch available' : 'Awaiting patch synthesis'}
                          </span>
                          <span className="text-[10px] text-slate-500 block mt-0.5">Verification status</span>
                        </div>
                      </div>

                      {/* Taint Trace Evidence summary */}
                      <div className="p-3 bg-slate-900 rounded-lg text-slate-200 font-mono text-[11px] space-y-1">
                        <div className="flex items-center gap-2 text-amber-400">
                          <span className="font-bold">[SOURCE]</span>
                          <span>{finding.taintTrace.source}</span>
                        </div>
                        <div className="flex items-center gap-2 text-rose-400">
                          <span className="font-bold">[SINK]</span>
                          <span>{finding.taintTrace.sink}</span>
                        </div>
                      </div>

                      {/* Action Bar inside Drawer */}
                      <div className="flex items-center justify-between pt-1 flex-wrap gap-2">
                        <span className="text-slate-500 text-[11px]">
                          Finding ID: <code className="font-mono text-slate-700 bg-white px-1.5 py-0.5 rounded border border-slate-200">{finding.id}</code>
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => navigate(`/verification?finding_id=${finding.id}`)}
                            className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-800 text-white rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
                          >
                            <Play className="w-3.5 h-3.5 fill-current" />
                            <span>Run Fix Verification</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => navigate(`/findings/${finding.id}`)}
                            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-medium shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
                          >
                            <span>Open Details</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Findings List - Compact Table View */}
        {!isLoading && filteredFindings.length > 0 && viewMode === 'table' && (
          <div className="bg-white border border-slate-200 rounded-xl shadow-2xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-xs font-semibold text-slate-600">
                    <th className="py-2.5 px-4">Severity</th>
                    <th className="py-2.5 px-4">Finding &amp; Category</th>
                    <th className="py-2.5 px-4">Repository &amp; Location</th>
                    <th className="py-2.5 px-4">Scanner</th>
                    <th className="py-2.5 px-4">Fix Status</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {filteredFindings.map(finding => {
                    const isFixReady = finding.remediationReadiness === 'VERIFIED_FIX_READY' || finding.remediationStatus === 'verified_patch';

                    return (
                      <tr
                        key={finding.id}
                        onClick={() => navigate(`/findings/${finding.id}`)}
                        className="hover:bg-slate-50/80 transition-colors cursor-pointer group"
                      >
                        {/* Severity */}
                        <td className="py-3 px-4 shrink-0">
                          <SeverityBadge severity={finding.severity} size="sm" />
                        </td>

                        {/* Title & CWE */}
                        <td className="py-3 px-4 max-w-sm">
                          <span className="font-semibold text-slate-900 block group-hover:text-blue-600 transition-colors truncate">
                            {finding.title}
                          </span>
                          <span className="text-[11px] text-slate-500 font-mono">
                            {finding.cwe}
                          </span>
                        </td>

                        {/* Repository & Location */}
                        <td className="py-3 px-4">
                          <div className="font-medium text-slate-800">{finding.repo}</div>
                          <div className="text-[11px] text-slate-500 font-mono truncate max-w-xs">
                            {finding.filePath}:{finding.line}
                          </div>
                        </td>

                        {/* Scanner Engine */}
                        <td className="py-3 px-4">
                          <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[11px] border border-slate-200">
                            {finding.engine}
                          </span>
                        </td>

                        {/* Fix Status */}
                        <td className="py-3 px-4">
                          {isFixReady ? (
                            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-700">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                              <span>Fix Ready</span>
                            </span>
                          ) : (
                            <span className="text-slate-500 text-[11px]">Needs Review</span>
                          )}
                        </td>

                        {/* Actions */}
                        <td className="py-3 px-4 text-right" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1.5">
                            {finding.diff && (
                              <button
                                type="button"
                                onClick={e => handleOpenDiff(finding, e)}
                                className="px-2 py-0.5 rounded border border-slate-200 text-[11px] font-medium text-blue-600 hover:bg-blue-50 cursor-pointer"
                              >
                                Diff
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => navigate(`/findings/${finding.id}`)}
                              className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 cursor-pointer"
                              title="Inspect finding details"
                            >
                              <ChevronRight className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Diff Modal */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={() => setActiveDiffItem(null)}
        isMerged={false}
      />
    </div>
  );
};