import React, { useState, useEffect } from 'react';
import { Shield, X, AlertCircle, Folder, CheckCircle2, ShieldCheck, Play, Loader2 } from 'lucide-react';
import { api, ScannerToolInfo, ScanResultDetail, ApiRepository } from '../../services/api';
import { TestSelector } from '../common/TestSelector';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: () => void;
  targetRepoName?: string;
  targetRepoId?: string;
  autoStart?: boolean;
  initialSelectedTools?: string[];
}

export const ScanModal: React.FC<ScanModalProps> = ({
  isOpen,
  onClose,
  onScanComplete,
  targetRepoName,
  targetRepoId,
  autoStart = false,
  initialSelectedTools,
}) => {
  const [scanSeconds, setScanSeconds] = useState(0);
  const [repositories, setRepositories] = useState<ApiRepository[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState<string>(targetRepoId || '');
  const [tools, setTools] = useState<ScannerToolInfo[]>([]);
  const [selectedToolNames, setSelectedToolNames] = useState<string[]>(initialSelectedTools || []);
  
  const [isLoadingTools, setIsLoadingTools] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string>('Preparing security scan...');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResultDetail | null>(null);

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
      setScanResult(null);
      setIsScanning(false);
      setStatusMessage('Preparing security scan...');
      
      // Load available tools from backend
      setIsLoadingTools(true);
      api.getScannerTools()
        .then((fetchedTools) => {
          const toolList = Array.isArray(fetchedTools) ? fetchedTools : [];
          setTools(toolList);
          const available = toolList.filter(t => t.is_available).map(t => t.name);
          const toolsToUse = (initialSelectedTools && initialSelectedTools.length > 0)
            ? initialSelectedTools.filter(name => available.includes(name))
            : available;
          const finalSelection = toolsToUse.length > 0 ? toolsToUse : available;
          setSelectedToolNames(finalSelection);

          if (autoStart && (targetRepoId || selectedRepoId)) {
            runScan(targetRepoId || selectedRepoId, finalSelection);
          }
        })
        .catch((err) => {
          console.error('Failed to load scanner tools:', err);
          setErrorMessage('Could not load scanner tool availability. Ensure backend is running.');
        })
        .finally(() => {
          setIsLoadingTools(false);
        });

      // Load repositories if targetRepoId not provided
      if (!targetRepoId) {
        api.getRepositories()
          .then((repos) => {
            setRepositories(repos);
            if (repos.length > 0 && !selectedRepoId) {
              setSelectedRepoId(repos[0].id);
            }
          })
          .catch((err) => {
            console.error('Failed to load repositories:', err);
          });
      } else {
        setSelectedRepoId(targetRepoId);
      }
    }
  }, [isOpen, targetRepoId]);

  const toggleTool = (toolName: string) => {
    setSelectedToolNames((prev) =>
      prev.includes(toolName) ? prev.filter((t) => t !== toolName) : [...prev, toolName]
    );
  };

  const runScan = async (repoId: string, toolsToRun: string[]) => {
    if (!repoId) {
      setErrorMessage('Please select a repository to scan.');
      return;
    }
    if (toolsToRun.length === 0) {
      setErrorMessage('Please select at least one security scanner to run.');
      return;
    }

    setIsScanning(true);
    setErrorMessage(null);
    setScanResult(null);
    setScanSeconds(0);
    setStatusMessage('Queueing security scan pipeline...');

    const timer = setInterval(() => {
      setScanSeconds((prev) => prev + 1);
    }, 1000);

    try {
      const scan = await api.triggerScan({
        repository_id: repoId,
        tools: toolsToRun,
        summary: `Automated security audit executed via pipeline`,
      });

      const pollIntervalMs = (typeof window !== 'undefined' && (window as any).__SCAN_POLL_INTERVAL__) || 1500;
      const maxAttempts = 60;
      let attempts = 0;
      let completed = false;

      while (!completed && attempts < maxAttempts) {
        attempts++;
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
        const statusData = await api.getScanStatus(scan.id);
        
        if (statusData.status === 'queued') {
          setStatusMessage('Scan queued, starting security analysis...');
        } else if (statusData.status === 'running') {
          setStatusMessage('Running Bandit, Semgrep, Trivy, pip-audit, and secret engines...');
        } else if (statusData.is_complete || ['completed', 'partial', 'failed', 'timed_out'].includes(statusData.status)) {
          completed = true;
          if (statusData.status === 'failed') {
            throw new Error(statusData.error_message || 'Scan execution failed on server.');
          }
        }
      }

      const results = await api.getScanResults(scan.id);
      setScanResult(results);
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('redmercury:api-connected'));
      }
    } catch (err: any) {
      console.error('Scan execution error:', err);
      setErrorMessage(err.message || 'Scan execution failed. Check repository workspace status.');
    } finally {
      clearInterval(timer);
      setIsScanning(false);
    }
  };

  const handleStartScan = () => {
    runScan(selectedRepoId, selectedToolNames);
  };

  const handleFinish = () => {
    onScanComplete();
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60">
      <div className="relative w-full max-w-2xl bg-white rounded-lg shadow-2xl border border-slate-200 flex flex-col max-h-[90vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-semibold text-slate-900 text-base">Run Security Analysis</h3>
              <p className="text-xs text-slate-500">
                Static Application Security Testing (SAST), Dependency Composition (SCA), and Secret Detection.
              </p>
            </div>
          </div>
          {!isScanning && (
            <button
              onClick={onClose}
              className="p-1 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5">
          {errorMessage && (
            <div className="p-3.5 rounded-md bg-rose-50 border border-rose-200 text-rose-700 text-xs flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-rose-500 mt-0.5 shrink-0" />
              <div className="flex-1">{errorMessage}</div>
            </div>
          )}

          {/* Configuration View (Before Scan) */}
          {!isScanning && !scanResult && (
            <>
              {/* Repository Target Selection */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1.5">
                  Target Repository
                </label>
                {targetRepoName ? (
                  <div className="px-3.5 py-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-medium text-slate-900 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Folder className="w-4 h-4 text-blue-600" />
                      <span>{targetRepoName}</span>
                    </div>
                    <span className="text-xs text-slate-500">Workspace isolated</span>
                  </div>
                ) : (
                  <select
                    value={selectedRepoId}
                    onChange={(e) => setSelectedRepoId(e.target.value)}
                    className="w-full px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-hidden"
                  >
                    {repositories.map((repo) => (
                      <option key={repo.id} value={repo.id}>
                        {repo.name} ({repo.source_type || 'local'}) — Health: {repo.health_score}%
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Security Scanner Engines & Test Suites */}
              <div className="space-y-2">
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider">
                  Select Security Tests to Execute
                </label>
                <TestSelector
                  tools={tools}
                  selectedTools={selectedToolNames}
                  onChange={setSelectedToolNames}
                  isLoading={isLoadingTools}
                />
              </div>

              <div className="p-3.5 rounded-md bg-blue-50 border border-blue-100 flex items-start gap-2.5 text-xs text-blue-900">
                <ShieldCheck className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                <div>
                  <strong>Isolated Static Analysis:</strong> Analysis executes strictly within an isolated sandbox without evaluating untrusted code. Secrets and access tokens are automatically redacted.
                </div>
              </div>
            </>
          )}

          {/* Running State */}
          {isScanning && (
            <div className="py-8 flex flex-col items-center justify-center text-center space-y-4">
              <Loader2 className="w-10 h-10 text-blue-600 animate-spin" />
              <div>
                <h4 className="font-semibold text-slate-900 text-base">Scanning Repository</h4>
                <p className="text-xs text-blue-600 font-medium mt-1 max-w-md">
                  {statusMessage}
                </p>
              </div>
              <div className="px-3 py-1.5 rounded-md bg-slate-50 border border-slate-200 text-xs text-slate-600 font-sans font-medium">
                Engines: {selectedToolNames.join(', ')}
              </div>
            </div>
          )}

          {/* Results View (After Scan) */}
          {scanResult && !isScanning && (
            <div className="space-y-4">
              {/* Scan Status Summary Card */}
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded-full ${
                      scanResult.status === 'completed'
                        ? 'bg-emerald-100 text-emerald-700 border border-emerald-300'
                        : scanResult.status === 'partial'
                        ? 'bg-amber-100 text-amber-700 border border-amber-300'
                        : 'bg-red-100 text-red-700 border border-red-300'
                    }`}>
                      {scanResult.status}
                    </span>
                    <span className="text-xs text-slate-500">Scan ID: {scanResult.id}</span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-4 text-sm text-slate-700">
                    <span>
                      Total Findings: <strong className="text-slate-900">{scanResult.total_findings}</strong>
                    </span>
                    {scanResult.health_score_after !== undefined && (
                      <span>
                        Health Score: <strong className="text-blue-600">{scanResult.health_score_after}%</strong>
                      </span>
                    )}
                  </div>
                </div>

                <div className="text-right">
                  <CheckCircle2 className="w-8 h-8 text-emerald-600" />
                </div>
              </div>

              {/* Scanners Breakdown Table */}
              <div>
                <h4 className="text-xs font-semibold text-slate-700 uppercase tracking-wider mb-2">
                  Scanner Execution Details
                </h4>
                <div className="border border-slate-200 rounded-lg overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100 text-slate-600 font-semibold border-b border-slate-200">
                      <tr>
                        <th className="px-3.5 py-2.5">Engine</th>
                        <th className="px-3.5 py-2.5">Category</th>
                        <th className="px-3.5 py-2.5">Duration</th>
                        <th className="px-3.5 py-2.5">Findings</th>
                        <th className="px-3.5 py-2.5">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 font-sans">
                      {scanResult.scanners.map((s, idx) => (
                        <tr key={idx} className="hover:bg-slate-50">
                          <td className="px-3.5 py-2.5 font-sans font-medium text-slate-900">
                            {s.scanner_name}
                            {s.version && (
                              <span className="block text-[11px] text-slate-400 font-mono">
                                {s.version}
                              </span>
                            )}
                          </td>
                          <td className="px-3.5 py-2.5 uppercase text-slate-600">{s.category}</td>
                          <td className="px-3.5 py-2.5 text-slate-600">{s.execution_time_seconds}s</td>
                          <td className="px-3.5 py-2.5 font-bold text-slate-900">
                            {s.findings_count}
                          </td>
                          <td className="px-3.5 py-2.5">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              s.status === 'success' || s.status === 'no_findings'
                                ? 'bg-emerald-50 text-emerald-700'
                                : 'bg-red-50 text-red-700'
                            }`}>
                              {s.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-3">
          {!isScanning && !scanResult && (
            <>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-md border border-slate-300 bg-white hover:bg-slate-50 text-slate-700 text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleStartScan}
                disabled={selectedToolNames.length === 0}
                aria-label="Execute Security Scan"
                className="flex items-center gap-2 px-5 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors shadow-xs disabled:opacity-50 cursor-pointer"
              >
                <Play className="w-4 h-4 fill-current" />
                <span>Execute Security Scan {selectedToolNames.length > 0 ? `(${selectedToolNames.length} Tests)` : ''}</span>
              </button>
            </>
          )}

          {scanResult && !isScanning && (
            <button
              onClick={handleFinish}
              className="px-5 py-2 rounded-md bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors shadow-xs"
            >
              View Findings &amp; Posture
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
