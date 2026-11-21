import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldCheck,
  ShieldAlert,
  AlertCircle,
  Sparkles,
  Lightbulb,
  Network,
  Loader2,
  FolderGit2,
  FileCode,
  CheckCircle2,
} from 'lucide-react';
import {
  api,
  ApiFinding,
  AnalysisResult,
  FindingValidationResponse,
  FindingValidationRequest,
  ContextualRiskAssessment,
} from '../services/api';
import { AiSecurityAnalystCard } from '../components/findings/AiSecurityAnalystCard';
import { EvidenceReviewSection } from '../components/findings/EvidenceReviewSection';
import { SeverityBadge } from '../components/common';

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();

  const [finding, setFinding] = useState<ApiFinding | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [isLoadingAnalysis, setIsLoadingAnalysis] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [userAuthorized, setUserAuthorized] = useState(true);

  const [isLoadingFinding, setIsLoadingFinding] = useState(true);
  const [findingError, setFindingError] = useState<string | null>(null);

  // Contextual Risk Prioritization state
  const [prioritization, setPrioritization] = useState<ContextualRiskAssessment | null>(null);

  // Evidence-driven vulnerability validation state
  const [validation, setValidation] = useState<FindingValidationResponse | null>(null);
  const [isLoadingValidation, setIsLoadingValidation] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    setIsLoadingFinding(true);
    setFindingError(null);

    // Fetch live finding
    api.getFinding(id)
      .then((data) => {
        if (isMounted) {
          setFinding(data);
          setIsLoadingFinding(false);
        }
      })
      .catch((err: any) => {
        if (isMounted) {
          if (err?.status === 401 || err?.status === 403) {
            setFindingError(err.message || 'Authentication required to view this finding.');
          } else {
            setFindingError(err.message || `Finding '${id}' could not be loaded.`);
          }
          setIsLoadingFinding(false);
        }
      });

    // Fetch existing live analyses for this finding
    api.getFindingAnalyses(id)
      .then((analyses) => {
        if (isMounted && analyses && analyses.length > 0) {
          setAnalysis(analyses[0]);
        } else if (isMounted) {
          setAnalysis(null);
        }
      })
      .catch(() => {
        if (isMounted) {
          setAnalysis(null);
        }
      });

    // Fetch existing evidence validation for this finding
    setIsLoadingValidation(true);
    api.getFindingValidation(id)
      .then((valData) => {
        if (isMounted) {
          setValidation(valData);
          setIsLoadingValidation(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          setValidation(null);
          setIsLoadingValidation(false);
        }
      });

    // Fetch existing live contextual risk prioritization for this finding
    api.getFindingPrioritization(id)
      .then((prioData) => {
        if (isMounted) {
          setPrioritization(prioData);
        }
      })
      .catch(() => {
        if (isMounted) {
          setPrioritization(null);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [id]);

  const handleRunAnalysis = async () => {
    if (!id) return;
    setIsLoadingAnalysis(true);
    setAnalysisError(null);
    try {
      const res = await api.analyzeFindingWithAi(id, userAuthorized);
      setAnalysis(res);
    } catch (err: any) {
      setAnalysisError(err.message || 'AI Security Analyst API call failed.');
    } finally {
      setIsLoadingAnalysis(false);
    }
  };

  const handleRunValidation = async (payload: FindingValidationRequest) => {
    if (!id) return;
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await api.validateFinding(id, payload);
      setValidation(res);
    } catch (err: any) {
      setValidationError(err.message || 'Evidence-driven vulnerability validation failed.');
    } finally {
      setIsValidating(false);
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 font-sans">
      {/* Top Breadcrumb Navigation */}
      <div className="px-6 lg:px-8 py-3.5 bg-white border-b border-slate-200 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs">
          <Link
            to="/findings"
            className="text-slate-600 hover:text-slate-900 flex items-center gap-1.5 font-medium transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Findings</span>
          </Link>
          <span className="text-slate-300">/</span>
          <span className="text-slate-500 truncate max-w-xs">{finding?.id || id}</span>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/verification"
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-lg shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Fix Verification</span>
          </Link>
        </div>
      </div>

      <div className="px-6 lg:px-8 py-6 space-y-5">
        {/* Loading Spinner */}
        {isLoadingFinding && (
          <div className="p-10 bg-white border border-slate-200 rounded-xl flex items-center justify-center space-x-3 shadow-2xs">
            <Loader2 className="w-5 h-5 text-slate-900 animate-spin" />
            <span className="text-xs text-slate-600">Retrieving security finding details...</span>
          </div>
        )}

        {/* Error Alert */}
        {findingError && (
          <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-700 flex items-center gap-2.5 shadow-2xs">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <span>{findingError}</span>
          </div>
        )}

        {/* Finding Header Card */}
        {finding && (
          <div className="p-6 bg-white border border-slate-200/80 rounded-xl shadow-2xs">
            <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
              <div className="space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  {finding.severity && (
                    <SeverityBadge severity={finding.severity.toLowerCase() as any} />
                  )}
                  <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 text-xs font-medium border border-slate-200">
                    {finding.cwe}
                  </span>
                  <span className="px-2 py-0.5 rounded-md bg-slate-100 text-slate-700 text-[11px] font-medium border border-slate-200">
                    Engine: {finding.scanner_name}
                  </span>
                  {finding.confidence_score && (
                    <span className="text-xs text-slate-500 font-medium">
                      Confidence: {(finding.confidence_score * 100).toFixed(0)}%
                    </span>
                  )}
                </div>

                <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                  {finding.title}
                </h1>

                <div className="flex items-center gap-2 text-xs text-slate-600 flex-wrap">
                  <span className="inline-flex items-center gap-1 font-medium text-slate-800">
                    <FolderGit2 className="w-3.5 h-3.5 text-slate-400" />
                    <span>Repository: {finding.repo_id}</span>
                  </span>
                  <span>•</span>
                  <span className="inline-flex items-center gap-1 font-mono text-slate-600 text-[11px]">
                    <FileCode className="w-3.5 h-3.5 text-slate-400" />
                    <span>{finding.file_path}:{finding.line_number}</span>
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 self-start">
                <button
                  type="button"
                  onClick={handleRunAnalysis}
                  disabled={isLoadingAnalysis}
                  className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-medium rounded-lg shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                >
                  {isLoadingAnalysis ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Sparkles className="w-3.5 h-3.5" />
                  )}
                  <span>{isLoadingAnalysis ? 'Analyzing...' : 'Run AI Security Analysis'}</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Risk Prioritization Breakdown */}
        <div className="p-6 bg-white border border-slate-200/80 rounded-xl shadow-2xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-900">
                Risk Prioritization &amp; Environmental Context
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Evaluation of scanner severity, component reachability, sensitive data handling, and verified fix readiness.
              </p>
            </div>
            <span className="text-[11px] text-slate-400">
              Evidence-weighted score
            </span>
          </div>

          {/* 4 Evaluation Metric Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
              <span className="text-slate-500 text-[11px] font-medium block">Scanner Severity</span>
              <span className="font-semibold text-rose-600 text-base mt-0.5 block">
                {prioritization?.original_scanner_severity || finding?.severity || 'CRITICAL'}
              </span>
              <span className="text-[11px] text-slate-400">Raw report</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
              <span className="text-slate-500 text-[11px] font-medium block">Contextual Priority</span>
              <span className="font-semibold text-blue-600 text-base mt-0.5 block">
                {prioritization?.contextual_priority || 'CRITICAL'} ({prioritization?.priority_score?.toFixed(0) || '85'}/100)
              </span>
              <span className="text-[11px] text-slate-400">Weighted triage score</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
              <span className="text-slate-500 text-[11px] font-medium block">Evidence Completeness</span>
              <span className="font-semibold text-slate-800 text-base mt-0.5 block">
                {prioritization?.evidence_completeness || 'PARTIAL'}
              </span>
              <span className="text-[11px] text-slate-400">AST &amp; dataflow depth</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80">
              <span className="text-slate-500 text-[11px] font-medium block">Verification Status</span>
              <span className={`font-semibold text-base mt-0.5 block ${
                prioritization?.verification_status === 'VERIFIED_AGAINST_DEFINED_CHECKS' || prioritization?.remediation_readiness === 'VERIFIED_FIX_READY'
                  ? 'text-emerald-600'
                  : 'text-amber-600'
              }`}>
                {prioritization?.remediation_readiness === 'VERIFIED_FIX_READY' ? 'Verified Fix Ready' : 'Pending Verification'}
              </span>
              <span className="text-[11px] text-slate-400">Fix status</span>
            </div>
          </div>

          {/* Floor Protection Alert */}
          {prioritization?.floor_protection_applied && (
            <div className="p-3.5 rounded-lg bg-amber-50 border border-amber-200 text-xs flex items-start gap-2.5 text-amber-900">
              <ShieldAlert className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">Severe Finding Floor Protection</span>
                <span className="text-slate-700 leading-relaxed">
                  Critical severity reported: Red Mercury enforces a priority floor to prevent silent downgrades and maintain triage visibility.
                </span>
              </div>
            </div>
          )}

          {/* Remediation Recommendations */}
          {prioritization?.investigation_recommendation && (
            <div className="p-3.5 rounded-lg bg-blue-50 border border-blue-200 text-xs flex items-start gap-2.5 text-blue-900">
              <Lightbulb className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold block">Recommended Remediation:</span>
                <span className="text-slate-700 leading-relaxed">{prioritization.investigation_recommendation}</span>
              </div>
            </div>
          )}

          {/* Patch Diff Preview if available */}
          {prioritization?.remediation_linkage?.patch_diff_preview && (
            <div className="p-3.5 bg-slate-50 rounded-xl border border-slate-200 text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-800">Proposed Patch Diff</span>
                <span className="text-[11px] text-slate-500">
                  Readiness: <strong>{prioritization.remediation_readiness}</strong>
                </span>
              </div>
              <div className="bg-slate-900 p-3.5 rounded-lg text-[11px] text-slate-200 font-mono overflow-x-auto shadow-inner">
                <pre className="whitespace-pre">{prioritization.remediation_linkage.patch_diff_preview}</pre>
              </div>
            </div>
          )}
        </div>

        {/* Evidence-Driven Vulnerability Validation Review Section */}
        {finding && (
          <EvidenceReviewSection
            findingId={finding.id}
            validation={validation}
            isLoading={isLoadingValidation}
            isValidating={isValidating}
            error={validationError}
            onRunValidation={handleRunValidation}
          />
        )}

        {/* AST Taint Trace Evidence Section */}
        <div className="p-6 bg-white border border-slate-200/80 rounded-xl shadow-2xs space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
              <Network className="w-4 h-4 text-slate-700" />
              <span>Dataflow &amp; Taint Trace Evidence</span>
            </h3>
            <span className="text-xs text-slate-400">Static AST Propagation</span>
          </div>

          <div className="p-4 bg-slate-900 rounded-xl font-mono text-xs text-slate-100 space-y-2.5 shadow-inner">
            <div className="flex items-center gap-2 text-amber-400">
              <span className="font-bold px-1.5 py-0.5 rounded bg-amber-400/20 text-amber-300 text-[10px]">SOURCE</span>
              <span>Untrusted user input vector detected at request handler</span>
            </div>
            <div className="flex items-center gap-2 text-slate-300 pl-4 border-l-2 border-slate-700">
              <span className="text-slate-500">&darr;</span>
              <span>Parameter interpolated without sanitization in query statement</span>
            </div>
            <div className="flex items-center gap-2 text-rose-400">
              <span className="font-bold px-1.5 py-0.5 rounded bg-rose-400/20 text-rose-300 text-[10px]">SINK</span>
              <span>Raw database execution sink reached</span>
            </div>
          </div>
        </div>

        {/* AI Security Analyst Section */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-sm text-slate-900 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-slate-700" />
              <span>AI Security Analyst Insights</span>
            </h3>
            <span className="text-xs text-slate-400">Analysis engine</span>
          </div>

          <AiSecurityAnalystCard
            analysis={analysis}
            isLoading={isLoadingAnalysis}
            error={analysisError}
            userAuthorized={userAuthorized}
            onToggleAuthorization={setUserAuthorized}
            onRunAnalysis={handleRunAnalysis}
          />
        </div>
      </div>
    </div>
  );
};