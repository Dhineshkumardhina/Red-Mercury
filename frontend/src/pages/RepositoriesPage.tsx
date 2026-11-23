import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Plus,
  Search,
  Table as TableIcon,
  LayoutGrid,
  FolderGit2,
  ShieldCheck,
  AlertTriangle,
  GitBranch,
  Play,
  ChevronRight,
  ArrowRight,
  X,
  UploadCloud,
  Folder,
  Archive,
  Loader2,
  CheckCircle2,
  FileCode,
  Sliders,
  ChevronUp,
  ChevronDown,
} from 'lucide-react';
import { api, ApiRepository, ScannerToolInfo } from '../services/api';
import { Repository, RepoHealth } from '../types';
import {
  ScanStatusIndicator,
  LoadingState,
  ErrorMessage,
  EmptyState,
  TestSelector,
} from '../components/common';
import { ScanModal } from '../components/modals/ScanModal';

type IngestionTab = 'zip' | 'local' | 'git';

export const RepositoriesPage: React.FC = () => {
  const navigate = useNavigate();

  const [liveRepos, setLiveRepos] = useState<ApiRepository[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [errorRequestId, setErrorRequestId] = useState<string | undefined>();

  // Filter and search
  const [search, setSearch] = useState('');
  const [healthFilter, setHealthFilter] = useState<'all' | 'secure' | 'at-risk' | 'vulnerable'>('all');
  const [viewType, setViewType] = useState<'table' | 'cards'>('table');

  // Ingestion Modal State
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<IngestionTab>('zip');
  const [newRepoName, setNewRepoName] = useState('');
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [localFolderPath, setLocalFolderPath] = useState('');
  const [newRepoUrl, setNewRepoUrl] = useState('');
  const [newRepoBranch, setNewRepoBranch] = useState('main');
  const [autoScanEnabled, setAutoScanEnabled] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [uploadSuccessMsg, setUploadSuccessMsg] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Security test selection state
  const [scannerTools, setScannerTools] = useState<ScannerToolInfo[]>([]);
  const [isLoadingTools, setIsLoadingTools] = useState(false);
  const [selectedIngestTools, setSelectedIngestTools] = useState<string[]>([
    'bandit',
    'injection_scanner',
    'owasp_tools',
    'gitleaks',
    'secret_detector',
    'pip_audit',
    'trivy_sca',
  ]);
  const [isCustomizingTests, setIsCustomizingTests] = useState(false);

  const isDesktop = typeof window !== 'undefined' && !!(window as any).electronAPI?.isElectron;

  // Scan modal
  const [scanModalTarget, setScanModalTarget] = useState<{
    id: string;
    name: string;
    autoStart?: boolean;
    initialSelectedTools?: string[];
  } | null>(null);

  // Load repositories from Backend API
  const loadRepositories = async () => {
    setIsLoading(true);
    setApiError(null);
    try {
      const repos = await api.getRepositories();
      setLiveRepos(repos || []);
    } catch (err: any) {
      setApiError(err.message || 'Unable to connect to backend repository API.');
      setErrorRequestId(err.requestId);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRepositories();
    setIsLoadingTools(true);
    api.getScannerTools()
      .then((tools) => {
        const toolList = Array.isArray(tools) ? tools : [];
        setScannerTools(toolList);
        const available = toolList.filter(t => t && t.is_available).map(t => t.name);
        const defaults = ['bandit', 'injection_scanner', 'owasp_tools', 'gitleaks', 'secret_detector', 'pip_audit', 'trivy_sca'].filter(name => available.includes(name));
        setSelectedIngestTools(defaults.length > 0 ? defaults : available);
      })
      .catch((err) => {
        console.error('Failed to load scanner tools:', err);
      })
      .finally(() => {
        setIsLoadingTools(false);
      });
  }, []);

  // Map live repositories into standardized format
  const combinedRepos: (Repository & {
    isLiveBackend?: boolean;
    sourceType?: string;
    ingestionStatus?: string;
    fileCount?: number;
    totalBytes?: number;
  })[] = useMemo(() => {
    return liveRepos.map(lr => ({
      id: lr.id,
      name: lr.name,
      branch: lr.default_branch,
      gitHash: lr.id.substring(0, 7),
      engine: lr.source_type === 'zip_upload' ? 'ZIP Archive' : lr.source_type === 'public_git' ? 'Git Clone' : 'Monitored',
      target: 'Production',
      health: (lr.critical_count > 0 ? 'vulnerable' : lr.high_count > 0 ? 'at-risk' : 'secure') as RepoHealth,
      findings: {
        critical: lr.critical_count,
        high: lr.high_count,
        medium: lr.medium_count,
        low: lr.low_count,
      },
      language: lr.language_metadata || (lr.name.includes('py') ? 'Python' : lr.name.includes('gateway') ? 'TypeScript' : 'Go'),
      lastScanned: new Date(lr.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      coverage: lr.health_score,
      autoRemediate: true,
      isLiveBackend: true,
      sourceType: lr.source_type,
      ingestionStatus: lr.ingestion_status,
      fileCount: lr.file_count,
      totalBytes: lr.total_size_bytes,
    }));
  }, [liveRepos]);

  // Statistics for KPI summary
  const stats = useMemo(() => {
    const total = combinedRepos.length;
    const secure = combinedRepos.filter(r => r.health === 'secure').length;
    const atRisk = combinedRepos.filter(r => r.health === 'at-risk').length;
    const vulnerable = combinedRepos.filter(r => r.health === 'vulnerable').length;
    return { total, secure, atRisk, vulnerable };
  }, [combinedRepos]);

  const filteredRepos = useMemo(() => {
    return combinedRepos.filter(repo => {
      const q = search.toLowerCase();
      const matchesSearch =
        !search ||
        repo.name.toLowerCase().includes(q) ||
        repo.language.toLowerCase().includes(q) ||
        repo.branch.toLowerCase().includes(q);
      const matchesHealth = healthFilter === 'all' || repo.health === healthFilter;
      return matchesSearch && matchesHealth;
    });
  }, [combinedRepos, search, healthFilter]);

  const resetModalForm = () => {
    setNewRepoName('');
    setZipFile(null);
    setLocalFolderPath('');
    setNewRepoUrl('');
    setNewRepoBranch('main');
    setRegisterError(null);
    setUploadSuccessMsg(null);
    setIsDragOver(false);
  };

  const handleBrowseLocalFolder = async () => {
    if ((window as any).electronAPI?.selectDirectory) {
      const selected = await (window as any).electronAPI.selectDirectory();
      if (selected) {
        setLocalFolderPath(selected);
        if (!newRepoName) {
          const parts = selected.replace(/\\/g, '/').split('/');
          setNewRepoName(parts[parts.length - 1] || 'local-repo');
        }
      }
    }
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      const file = files[0];
      if (file.name.endsWith('.zip')) {
        setZipFile(file);
        if (!newRepoName) {
          setNewRepoName(file.name.replace(/\.zip$/i, ''));
        }
      } else {
        setRegisterError('Please select a valid ZIP archive (.zip)');
      }
    }
  };

  const handleIngestRepo = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setRegisterError(null);
    setUploadSuccessMsg(null);

    try {
      let created: ApiRepository | null = null;

      if (activeTab === 'zip') {
        if (!zipFile) {
          throw new Error('Please select a valid ZIP archive containing source code.');
        }
        created = await api.ingestZipArchive(zipFile, newRepoName.trim() || undefined);
      } else if (activeTab === 'local') {
        if (!localFolderPath.trim()) {
          throw new Error('Please specify or select a local project directory.');
        }
        created = await api.ingestLocalDirectory({
          local_path: localFolderPath.trim(),
          name: newRepoName.trim() || undefined,
        });
      } else if (activeTab === 'git') {
        if (!newRepoUrl.trim()) {
          throw new Error('Please enter a valid HTTPS Git repository URL.');
        }
        created = await api.ingestGitRepository({
          git_url: newRepoUrl.trim(),
          name: newRepoName.trim() || undefined,
          default_branch: newRepoBranch.trim() || 'main',
        });
      }

      if (created && autoScanEnabled) {
        const repoCreated = created;
        setIsRegisterModalOpen(false);
        resetModalForm();
        await loadRepositories();
        setScanModalTarget({
          id: repoCreated.id,
          name: repoCreated.name,
          autoStart: true,
          initialSelectedTools: selectedIngestTools,
        });
        return;
      }

      setUploadSuccessMsg(`Repository "${created?.name || newRepoName}" added successfully.`);
      await loadRepositories();
      setTimeout(() => {
        setIsRegisterModalOpen(false);
        resetModalForm();
      }, 1000);
    } catch (err: any) {
      setRegisterError(err.message || 'Repository ingestion failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Page Header */}
      <div className="px-6 lg:px-8 py-5 bg-white border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">
              Repositories
            </h1>
            <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 text-xs font-medium border border-slate-200">
              {combinedRepos.length} connected
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Source code repositories monitored for vulnerabilities, code health, and branch protection.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => {
              resetModalForm();
              setIsRegisterModalOpen(true);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs shadow-xs transition-colors cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add Repository</span>
          </button>
        </div>
      </div>

      {/* Main Container */}
      <div className="px-6 lg:px-8 py-6 space-y-5">
        {/* KPI Metric Summary Strip */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Total Monitored
              </span>
              <span className="text-2xl font-semibold text-slate-900 tracking-tight mt-1 block">
                {stats.total}
              </span>
              <span className="text-xs text-slate-500 mt-0.5 block">Active source codebases</span>
            </div>
            <div className="p-2.5 rounded-lg bg-slate-100 text-slate-700">
              <FolderGit2 className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Secure Codebases
              </span>
              <span className="text-2xl font-semibold text-emerald-600 tracking-tight mt-1 block">
                {stats.secure}
              </span>
              <span className="text-xs text-emerald-600 mt-0.5 block">Zero critical or high findings</span>
            </div>
            <div className="p-2.5 rounded-lg bg-emerald-50 text-emerald-600 border border-emerald-100">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>

          <div className="bg-white rounded-xl p-4 border border-slate-200/80 shadow-2xs flex items-center justify-between">
            <div>
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block">
                Attention Required
              </span>
              <span className="text-2xl font-semibold text-rose-600 tracking-tight mt-1 block">
                {stats.vulnerable + stats.atRisk}
              </span>
              <span className="text-xs text-rose-600 mt-0.5 block">
                {stats.vulnerable} vulnerable • {stats.atRisk} at-risk
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-rose-50 text-rose-600 border border-rose-100">
              <AlertTriangle className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Filter and View Controls Strip */}
        <div className="bg-white rounded-xl border border-slate-200/80 shadow-2xs p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-1 flex-wrap">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[220px] max-w-sm">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search repository or language..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-50 hover:bg-slate-100/60 focus:bg-white border border-slate-200 focus:border-slate-400 rounded-lg text-xs text-slate-800 placeholder:text-slate-400 focus:outline-hidden transition-colors"
              />
            </div>

            {/* Health Filter Chips */}
            <div className="flex items-center gap-1.5 overflow-x-auto">
              {(
                [
                  { key: 'all', label: 'All', count: stats.total },
                  { key: 'secure', label: 'Secure', count: stats.secure },
                  { key: 'at-risk', label: 'At Risk', count: stats.atRisk },
                  { key: 'vulnerable', label: 'Vulnerable', count: stats.vulnerable },
                ] as const
              ).map(f => (
                <button
                  key={f.key}
                  type="button"
                  onClick={() => setHealthFilter(f.key)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors border flex items-center gap-1.5 cursor-pointer ${
                    healthFilter === f.key
                      ? 'bg-slate-900 text-white border-slate-900 shadow-2xs'
                      : 'bg-white text-slate-600 hover:text-slate-900 border-slate-200 hover:bg-slate-50'
                  }`}
                >
                  <span>{f.label}</span>
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                      healthFilter === f.key ? 'bg-slate-800 text-slate-200' : 'bg-slate-100 text-slate-500'
                    }`}
                  >
                    {f.count}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* View Toggle */}
          <div className="flex items-center gap-1 border border-slate-200 rounded-lg p-0.5 bg-slate-50 self-end sm:self-auto shrink-0">
            <button
              type="button"
              onClick={() => setViewType('table')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                viewType === 'table' ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <TableIcon className="w-3.5 h-3.5" />
              <span>Table</span>
            </button>
            <button
              type="button"
              onClick={() => setViewType('cards')}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                viewType === 'cards' ? 'bg-white text-slate-900 font-semibold shadow-2xs' : 'text-slate-500 hover:text-slate-800'
              }`}
            >
              <LayoutGrid className="w-3.5 h-3.5" />
              <span>Cards</span>
            </button>
          </div>
        </div>

        {/* Content Body */}
        {isLoading && <LoadingState message="Loading repositories..." />}

        {apiError && (
          <ErrorMessage
            title="Backend Connection Notice"
            message={apiError}
            requestId={errorRequestId}
            onRetry={loadRepositories}
          />
        )}

        {!isLoading && filteredRepos.length === 0 ? (
          <EmptyState
            icon="folder_off"
            title="No repositories found"
            description={search ? `No repositories match "${search}".` : 'No repositories are currently connected.'}
            actionLabel="Add Repository"
            onAction={() => {
              resetModalForm();
              setIsRegisterModalOpen(true);
            }}
          />
        ) : viewType === 'table' ? (
          /* Table View */
          <div className="bg-white border border-slate-200 rounded-xl shadow-2xs overflow-hidden">
            <div className="overflow-x-auto w-full">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-semibold uppercase text-slate-500 tracking-wider">
                    <th className="py-3 px-4 font-semibold">Repository</th>
                    <th className="py-3 px-4 font-semibold">Status</th>
                    <th className="py-3 px-4 font-semibold">Branch</th>
                    <th className="py-3 px-4 font-semibold">Open Findings</th>
                    <th className="py-3 px-4 font-semibold">Health Score</th>
                    <th className="py-3 px-4 font-semibold">Source</th>
                    <th className="py-3 px-4 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredRepos.map(repo => (
                    <tr
                      key={repo.id}
                      onClick={() => navigate(`/repositories/${repo.id}`)}
                      className="hover:bg-slate-50/70 transition-colors cursor-pointer group"
                    >
                      {/* Name & Language */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2.5">
                          <div className="p-1.5 rounded-md bg-slate-100 text-slate-600 group-hover:text-blue-600 group-hover:bg-blue-50 transition-colors shrink-0">
                            <FolderGit2 className="w-4 h-4" />
                          </div>
                          <div>
                            <span className="font-semibold text-slate-900 group-hover:text-blue-600 transition-colors block">
                              {repo.name}
                            </span>
                            <div className="flex items-center gap-1.5 text-[11px] text-slate-500 mt-0.5">
                              <span>{repo.language}</span>
                              {repo.fileCount !== undefined && repo.fileCount > 0 && (
                                <>
                                  <span>•</span>
                                  <span>{repo.fileCount} files</span>
                                </>
                              )}
                              {repo.totalBytes !== undefined && repo.totalBytes > 0 && (
                                <>
                                  <span>•</span>
                                  <span>{formatFileSize(repo.totalBytes)}</span>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-3 px-4">
                        <ScanStatusIndicator status={repo.health} />
                      </td>

                      {/* Branch */}
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                          <GitBranch className="w-3 h-3 text-slate-500" />
                          <span>{repo.branch}</span>
                        </span>
                      </td>

                      {/* Open Findings */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 text-[11px]">
                          {repo.findings.critical > 0 && (
                            <span className="px-2 py-0.5 rounded-md bg-rose-50 text-rose-700 font-semibold border border-rose-200">
                              {repo.findings.critical} Crit
                            </span>
                          )}
                          {repo.findings.high > 0 && (
                            <span className="px-2 py-0.5 rounded-md bg-amber-50 text-amber-800 font-medium border border-amber-200">
                              {repo.findings.high} High
                            </span>
                          )}
                          {repo.findings.critical === 0 && repo.findings.high === 0 && (
                            <span className="px-2 py-0.5 rounded-md bg-emerald-50 text-emerald-700 font-medium border border-emerald-200">
                              Clean
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Health Score */}
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full ${
                                repo.coverage >= 90
                                  ? 'bg-emerald-500'
                                  : repo.coverage >= 70
                                  ? 'bg-amber-500'
                                  : 'bg-rose-500'
                              }`}
                              style={{ width: `${repo.coverage}%` }}
                            />
                          </div>
                          <span className="text-xs font-semibold text-slate-700">
                            {repo.coverage}%
                          </span>
                        </div>
                      </td>

                      {/* Source */}
                      <td className="py-3 px-4">
                        <span className="text-[11px] text-slate-500 px-2 py-0.5 rounded bg-slate-50 border border-slate-200">
                          {repo.engine}
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setScanModalTarget({ id: repo.id, name: repo.name })}
                            className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 rounded-md transition-colors cursor-pointer shadow-2xs"
                            title="Run Security Scan"
                          >
                            <Play className="w-3 h-3 text-slate-500 fill-current" />
                            <span>Scan</span>
                          </button>
                          <button
                            type="button"
                            onClick={() => navigate(`/repositories/${repo.id}`)}
                            className="p-1 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded transition-colors cursor-pointer"
                            title="Inspect details"
                          >
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          /* Cards View */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredRepos.map(repo => (
              <div
                key={repo.id}
                onClick={() => navigate(`/repositories/${repo.id}`)}
                className="p-4 rounded-xl bg-white border border-slate-200 hover:border-slate-300 hover:shadow-xs transition-all cursor-pointer flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-2.5">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className="p-1.5 rounded-md bg-slate-100 text-slate-600 group-hover:text-blue-600 group-hover:bg-blue-50 transition-colors shrink-0">
                        <FolderGit2 className="w-4 h-4" />
                      </div>
                      <h3 className="font-semibold text-slate-900 text-sm truncate" title={repo.name}>
                        {repo.name}
                      </h3>
                    </div>
                    <ScanStatusIndicator status={repo.health} />
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-slate-500 mb-3">
                    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-100 text-slate-700">
                      <GitBranch className="w-3 h-3 text-slate-400" />
                      <span>{repo.branch}</span>
                    </span>
                    <span>•</span>
                    <span>{repo.language}</span>
                    {repo.fileCount !== undefined && repo.fileCount > 0 && (
                      <>
                        <span>•</span>
                        <span>{repo.fileCount} files</span>
                      </>
                    )}
                  </div>

                  <div className="flex items-center gap-2 mb-2">
                    <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          repo.coverage >= 90
                            ? 'bg-emerald-500'
                            : repo.coverage >= 70
                            ? 'bg-amber-500'
                            : 'bg-rose-500'
                        }`}
                        style={{ width: `${repo.coverage}%` }}
                      />
                    </div>
                    <span className="text-xs font-semibold text-slate-700">
                      {repo.coverage}% health
                    </span>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-100 flex items-center justify-between mt-3">
                  <div className="flex items-center gap-1.5 text-xs">
                    {repo.findings.critical > 0 ? (
                      <span className="text-rose-600 font-semibold">{repo.findings.critical} Critical</span>
                    ) : (
                      <span className="text-emerald-600 font-medium">0 Critical</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={e => {
                        e.stopPropagation();
                        setScanModalTarget({ id: repo.id, name: repo.name });
                      }}
                      className="px-2 py-0.5 text-xs font-medium text-slate-700 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 rounded transition-colors"
                    >
                      Scan
                    </button>
                    <span className="text-xs font-medium text-blue-600 group-hover:underline flex items-center gap-0.5">
                      <span>Inspect</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add Repository Modal */}
      {isRegisterModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-100">
          <div className="bg-white rounded-2xl shadow-xl border border-slate-200 max-w-lg w-full p-6 animate-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between pb-3.5 border-b border-slate-100">
              <div className="flex items-center gap-2.5">
                <div className="p-1.5 rounded-lg bg-slate-100 text-slate-800">
                  <FolderGit2 className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="font-semibold text-base text-slate-900">Add Repository</h3>
                  <p className="text-xs text-slate-500">Connect a codebase for vulnerability analysis.</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsRegisterModalOpen(false)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Ingestion Method Tabs */}
            <div className="grid grid-cols-3 gap-1 p-1 bg-slate-100 rounded-lg text-xs font-medium mt-4">
              <button
                type="button"
                onClick={() => setActiveTab('zip')}
                className={`py-1.5 px-2 rounded-md transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  activeTab === 'zip'
                    ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Archive className="w-3.5 h-3.5" />
                <span>ZIP Archive</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('local')}
                className={`py-1.5 px-2 rounded-md transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  activeTab === 'local'
                    ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Folder className="w-3.5 h-3.5" />
                <span>Local Folder</span>
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('git')}
                className={`py-1.5 px-2 rounded-md transition-all cursor-pointer flex items-center justify-center gap-1.5 ${
                  activeTab === 'git'
                    ? 'bg-white text-slate-900 font-semibold shadow-2xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" />
                <span>Git Clone</span>
              </button>
            </div>

            <form onSubmit={handleIngestRepo} className="mt-4 space-y-4">
              {registerError && (
                <div className="p-3 rounded-lg bg-rose-50 border border-rose-200 text-xs text-rose-700 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>{registerError}</span>
                </div>
              )}

              {uploadSuccessMsg && (
                <div className="p-3 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{uploadSuccessMsg}</span>
                </div>
              )}

              {/* Tab 1: ZIP File Upload */}
              {activeTab === 'zip' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1.5">
                      ZIP Archive (.zip) *
                    </label>

                    {/* Drag and Drop Zone */}
                    <div
                      onDragOver={e => {
                        e.preventDefault();
                        setIsDragOver(true);
                      }}
                      onDragLeave={() => setIsDragOver(false)}
                      onDrop={handleFileDrop}
                      onClick={() => fileInputRef.current?.click()}
                      className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-colors ${
                        isDragOver
                          ? 'border-blue-500 bg-blue-50/50'
                          : zipFile
                          ? 'border-emerald-300 bg-emerald-50/30'
                          : 'border-slate-200 hover:border-slate-300 bg-slate-50/50'
                      }`}
                    >
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".zip,application/zip"
                        className="hidden"
                        onChange={e => {
                          const file = e.target.files?.[0] || null;
                          setZipFile(file);
                          if (file && !newRepoName) {
                            setNewRepoName(file.name.replace(/\.zip$/i, ''));
                          }
                        }}
                      />

                      {zipFile ? (
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2.5 text-left">
                            <div className="p-2 rounded-lg bg-emerald-100 text-emerald-700">
                              <FileCode className="w-5 h-5" />
                            </div>
                            <div>
                              <p className="text-xs font-semibold text-slate-900 truncate max-w-[240px]">
                                {zipFile.name}
                              </p>
                              <p className="text-[11px] text-slate-500">
                                {formatFileSize(zipFile.size)}
                              </p>
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={e => {
                              e.stopPropagation();
                              setZipFile(null);
                            }}
                            className="p-1 rounded-md text-slate-400 hover:text-rose-600 hover:bg-white transition-colors cursor-pointer"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center">
                          <UploadCloud className="w-8 h-8 text-slate-400 mb-2" />
                          <p className="text-xs font-medium text-slate-700">
                            Click to upload or drag and drop
                          </p>
                          <p className="text-[11px] text-slate-400 mt-0.5">
                            Standard source code ZIP files up to 100MB
                          </p>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Repository Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={newRepoName}
                      onChange={e => setNewRepoName(e.target.value)}
                      placeholder="e.g. backend-api"
                      className="w-full px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                    />
                  </div>
                </>
              )}

              {/* Tab 2: Local Folder */}
              {activeTab === 'local' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Local Directory Path *
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        required
                        value={localFolderPath}
                        onChange={e => {
                          setLocalFolderPath(e.target.value);
                          if (!newRepoName && e.target.value) {
                            const clean = e.target.value.replace(/\\/g, '/');
                            const parts = clean.split('/').filter(Boolean);
                            if (parts.length > 0) setNewRepoName(parts[parts.length - 1]);
                          }
                        }}
                        placeholder="C:\projects\my-codebase"
                        className="flex-1 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                      />
                      {isDesktop && (
                        <button
                          type="button"
                          onClick={handleBrowseLocalFolder}
                          className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-medium rounded-lg border border-slate-200 cursor-pointer transition-colors"
                        >
                          Browse
                        </button>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">
                      Path to the root folder containing your project files.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Repository Name (Optional)
                    </label>
                    <input
                      type="text"
                      value={newRepoName}
                      onChange={e => setNewRepoName(e.target.value)}
                      placeholder="e.g. backend-api"
                      className="w-full px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                    />
                  </div>
                </>
              )}

              {/* Tab 3: Git Clone */}
              {activeTab === 'git' && (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1">
                      Git Repository HTTPS URL *
                    </label>
                    <input
                      type="url"
                      required
                      value={newRepoUrl}
                      onChange={e => {
                        setNewRepoUrl(e.target.value);
                        if (!newRepoName && e.target.value) {
                          const match = e.target.value.match(/\/([^/]+?)(\.git)?$/);
                          if (match && match[1]) setNewRepoName(match[1]);
                        }
                      }}
                      placeholder="https://github.com/organization/repo.git"
                      className="w-full px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-2.5">
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 mb-1">
                        Name (Optional)
                      </label>
                      <input
                        type="text"
                        value={newRepoName}
                        onChange={e => setNewRepoName(e.target.value)}
                        placeholder="repo-name"
                        className="w-full px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-slate-700 mb-1">
                        Branch
                      </label>
                      <input
                        type="text"
                        value={newRepoBranch}
                        onChange={e => setNewRepoBranch(e.target.value)}
                        placeholder="main"
                        className="w-full px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:border-slate-400 focus:outline-hidden transition-colors"
                      />
                    </div>
                  </div>
                </>
              )}

              {/* Security Test Selection Section */}
              <div className="pt-2.5 border-t border-slate-100 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="autoScanCheck"
                      checked={autoScanEnabled}
                      onChange={e => setAutoScanEnabled(e.target.checked)}
                      className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-blue-500 cursor-pointer"
                    />
                    <label htmlFor="autoScanCheck" className="text-xs font-semibold text-slate-800 cursor-pointer select-none flex items-center gap-1.5">
                      <ShieldCheck className="w-4 h-4 text-blue-600" />
                      <span>Run Security Tests on this {activeTab === 'zip' ? 'ZIP archive' : 'repository'}</span>
                    </label>
                  </div>

                  {autoScanEnabled && (
                    <button
                      type="button"
                      onClick={() => setIsCustomizingTests(prev => !prev)}
                      className="inline-flex items-center gap-1 text-[11px] font-medium text-blue-600 hover:text-blue-800 hover:underline cursor-pointer"
                    >
                      <Sliders className="w-3 h-3" />
                      <span>{isCustomizingTests ? 'Collapse tests' : `Choose tests (${selectedIngestTools.length} selected)`}</span>
                      {isCustomizingTests ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    </button>
                  )}
                </div>

                {autoScanEnabled && (
                  <div className="mt-2 p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-2.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-600 text-[11px] font-medium">
                        Choose what tests to execute on the uploaded {activeTab === 'zip' ? 'ZIP code' : 'repository'}:
                      </span>
                      <span className="font-semibold text-blue-700 bg-blue-100/70 border border-blue-200 px-2 py-0.5 rounded-full text-[10px]">
                        {selectedIngestTools.length} tests active
                      </span>
                    </div>

                    <TestSelector
                      tools={scannerTools}
                      selectedTools={selectedIngestTools}
                      onChange={setSelectedIngestTools}
                      isLoading={isLoadingTools}
                      compact={true}
                    />
                  </div>
                )}
              </div>

              {/* Live Ingestion Progress Feedback */}
              {isSubmitting && (
                <div className="p-3 bg-blue-50 border border-blue-200 rounded-lg text-xs text-blue-900 flex items-center gap-2.5">
                  <Loader2 className="w-4 h-4 text-blue-600 animate-spin shrink-0" />
                  <div>
                    <span className="font-semibold block">
                      {activeTab === 'zip'
                        ? 'Extracting and indexing archive...'
                        : activeTab === 'git'
                        ? 'Cloning repository and analyzing structure...'
                        : 'Indexing local directory files...'}
                    </span>
                    <p className="text-[11px] text-blue-700 mt-0.5">
                      Extracting files, scanning extensions, and initializing security gates...
                    </p>
                  </div>
                </div>
              )}

              {/* Modal Buttons */}
              <div className="pt-3.5 border-t border-slate-100 flex items-center justify-end gap-2.5">
                <button
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => setIsRegisterModalOpen(false)}
                  className="px-3.5 py-1.5 border border-slate-200 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || (autoScanEnabled && selectedIngestTools.length === 0)}
                  className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors flex items-center gap-1.5 disabled:opacity-50 cursor-pointer"
                >
                  {isSubmitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                  <span>
                    {isSubmitting
                      ? 'Ingesting...'
                      : autoScanEnabled
                      ? `Add & Run ${selectedIngestTools.length} Tests`
                      : 'Add Repository'}
                  </span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Trigger Scan Modal */}
      {scanModalTarget && (
        <ScanModal
          isOpen={!!scanModalTarget}
          targetRepoId={scanModalTarget.id}
          targetRepoName={scanModalTarget.name}
          autoStart={scanModalTarget.autoStart}
          initialSelectedTools={scanModalTarget.initialSelectedTools}
          onClose={() => setScanModalTarget(null)}
          onScanComplete={() => {
            const targetId = scanModalTarget.id;
            setScanModalTarget(null);
            loadRepositories();
            navigate(`/repositories/${targetId}`);
          }}
        />
      )}
    </div>
  );
};