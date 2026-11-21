import React, { useState } from 'react';
import {
  FileCheck,
  Play,
  Info,
  AlertCircle,
  CheckCircle2,
  GitPullRequest,
  SearchX,
  UserCheck,
  HelpCircle,
  Sparkles,
  Lock,
  Code2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Fingerprint,
  Shield,
  Loader2,
} from 'lucide-react';
import {
  FindingValidationResponse,
  FindingValidationRequest,
  ValidationStatusEnum,
} from '../../services/api';

export interface EvidenceReviewSectionProps {
  findingId: string;
  validation: FindingValidationResponse | null;
  isLoading: boolean;
  isValidating: boolean;
  error: string | null;
  onRunValidation: (payload: FindingValidationRequest) => Promise<void>;
}

export const EvidenceReviewSection: React.FC<EvidenceReviewSectionProps> = ({
  findingId,
  validation,
  isLoading,
  isValidating,
  error,
  onRunValidation,
}) => {
  const [useAiAssistant, setUseAiAssistant] = useState(false);
  const [showFullHash, setShowFullHash] = useState(false);

  const handleValidateClick = () => {
    onRunValidation({
      use_ai_assistant: useAiAssistant,
      user_authorized: true,
    });
  };

  const getStatusBadge = (status: ValidationStatusEnum | undefined) => {
    switch (status) {
      case 'SUPPORTED_BY_EVIDENCE':
        return {
          label: 'Supported by Evidence',
          icon: CheckCircle2,
          bg: 'bg-emerald-50',
          text: 'text-emerald-800',
          border: 'border-emerald-200',
          badgeBg: 'bg-emerald-600',
        };
      case 'POSSIBLE_FALSE_POSITIVE':
        return {
          label: 'Possible False Positive',
          icon: GitPullRequest,
          bg: 'bg-amber-50',
          text: 'text-amber-800',
          border: 'border-amber-200',
          badgeBg: 'bg-amber-600',
        };
      case 'INSUFFICIENT_EVIDENCE':
        return {
          label: 'Insufficient Evidence',
          icon: SearchX,
          bg: 'bg-slate-100',
          text: 'text-slate-800',
          border: 'border-slate-200',
          badgeBg: 'bg-slate-600',
        };
      case 'HUMAN_REVIEW_REQUIRED':
        return {
          label: 'Human Review Required',
          icon: UserCheck,
          bg: 'bg-purple-50',
          text: 'text-purple-800',
          border: 'border-purple-200',
          badgeBg: 'bg-purple-600',
        };
      case 'UNREVIEWED':
      default:
        return {
          label: 'Unreviewed',
          icon: HelpCircle,
          bg: 'bg-blue-50',
          text: 'text-blue-800',
          border: 'border-blue-200',
          badgeBg: 'bg-blue-600',
        };
    }
  };

  const currentStatusBadge = getStatusBadge(validation?.assessment_status);
  const StatusIcon = currentStatusBadge.icon;

  return (
    <div className="rounded-xl bg-white border border-slate-200/80 shadow-2xs overflow-hidden font-sans">
      {/* Module Header & Action Bar */}
      <div className="bg-slate-900 text-white px-5 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-slate-800 text-slate-300 border border-slate-700">
              <FileCheck className="w-4 h-4" />
            </div>
            <h3 className="font-semibold text-sm tracking-normal">
              Evidence-Driven Vulnerability Validation
            </h3>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300 border border-slate-700">
              VALIDATION ENGINE
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Assesses existing scanner findings against observable code context, data-flow signals, and AST patterns without mutating original scanner results.
          </p>
        </div>

        {/* Validation Trigger Controls */}
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={useAiAssistant}
              onChange={(e) => setUseAiAssistant(e.target.checked)}
              className="rounded border-slate-700 bg-slate-800 text-slate-900 focus:ring-slate-900 h-3.5 w-3.5 cursor-pointer"
            />
            <span className="text-xs font-medium text-slate-300">
              Enable AI Assistant
            </span>
          </label>

          <button
            type="button"
            onClick={handleValidateClick}
            disabled={isValidating || isLoading}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
              isValidating || isLoading
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed border border-slate-700'
                : 'bg-white text-slate-900 hover:bg-slate-100 shadow-xs'
            }`}
          >
            {isValidating ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Evaluating Evidence...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Evaluate Evidence</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scope Notice */}
      <div className="bg-amber-50/60 border-b border-amber-200/80 px-5 py-2.5 flex items-center gap-2 text-xs text-amber-900">
        <Info className="w-4 h-4 text-amber-600 shrink-0" />
        <span>
          <strong>Validation Scope:</strong> Assessment statuses evaluate the strength of available evidence and test results; manual code review remains recommended for high-impact production paths.
        </span>
      </div>

      <div className="p-5 space-y-5">
        {/* Loading Indicator */}
        {isLoading && !validation && (
          <div className="py-8 flex flex-col items-center justify-center space-y-2.5">
            <Loader2 className="w-6 h-6 text-slate-900 animate-spin" />
            <p className="text-xs text-slate-600 font-medium">Loading validation state...</p>
          </div>
        )}

        {/* Error Notice */}
        {error && (
          <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-xs flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
            <div>
              <span className="font-semibold mr-1">Validation Notice:</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Main Assessment Presentation */}
        {validation && (
          <>
            {/* Assessment Status Banner */}
            <div className={`p-4 rounded-xl border ${currentStatusBadge.bg} ${currentStatusBadge.border} flex flex-col sm:flex-row sm:items-center justify-between gap-3`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg text-white ${currentStatusBadge.badgeBg}`}>
                  <StatusIcon className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                      VALIDATION STATUS:
                    </span>
                    <span className={`font-semibold text-sm ${currentStatusBadge.text}`}>
                      {validation.assessment_status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700 mt-0.5">
                    {validation.evidence_summary}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-4 text-xs self-start sm:self-auto">
                <div className="text-right">
                  <span className="text-slate-500 text-[10px] uppercase font-semibold block">Confidence Level</span>
                  <span className="font-semibold text-slate-800">
                    {validation.confidence_level} ({Math.round(validation.confidence_score * 100)}%)
                  </span>
                </div>
                {validation.ai_assisted && (
                  <div className="px-2 py-1 rounded-md bg-white border border-slate-200 text-xs text-slate-700 flex items-center gap-1.5 shadow-2xs">
                    <Sparkles className="w-3.5 h-3.5 text-blue-600" />
                    <span>Automated ({validation.ai_model || 'Security Engine'})</span>
                  </div>
                )}
              </div>
            </div>

            {/* Assessment Detailed Explanation */}
            <div className="p-4 bg-slate-50/70 rounded-xl border border-slate-200/80 text-xs space-y-1.5">
              <span className="font-semibold uppercase tracking-wider text-slate-600 text-[11px] block">
                Evidence-Based Rationale:
              </span>
              <p className="text-slate-800 leading-relaxed">
                {validation.explanation}
              </p>
            </div>

            {/* Preserved Original Scanner Finding */}
            {validation.original_finding && (
              <div className="p-4 bg-white rounded-xl border border-slate-200/80 shadow-2xs space-y-3">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                  <div className="flex items-center gap-2">
                    <Lock className="w-4 h-4 text-slate-500" />
                    <h4 className="font-semibold text-xs uppercase tracking-wider text-slate-800">
                      Original Scanner Finding (Preserved &amp; Unmodified)
                    </h4>
                  </div>
                  <span className="text-[11px] text-slate-500">
                    Severity Pristinely Preserved
                  </span>
                </div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/70">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block">Scanner Tool</span>
                    <span className="font-medium text-slate-900 mt-0.5 block">{validation.original_finding.scanner_name || 'N/A'}</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/70">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block">Scanner Severity</span>
                    <span className="font-semibold text-rose-600 mt-0.5 block">{validation.original_finding.original_severity || 'UNKNOWN'}</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/70">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block">Rule Identifier</span>
                    <span className="font-mono text-slate-900 mt-0.5 block truncate text-[11px]" title={validation.original_finding.rule_identifier}>
                      {validation.original_finding.rule_identifier || 'N/A'}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200/70">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block">Target Code Location</span>
                    <span className="font-mono text-slate-900 mt-0.5 block truncate text-[11px]" title={`${validation.original_finding.file_path}:${validation.original_finding.line_number}`}>
                      {validation.original_finding.file_path}:{validation.original_finding.line_number}
                    </span>
                  </div>
                </div>

                {validation.original_finding.scanner_message && (
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200/70 text-xs text-slate-700">
                    <span className="text-[10px] text-slate-500 uppercase font-semibold block mb-0.5">Original Scanner Message:</span>
                    <p className="leading-relaxed">{validation.original_finding.scanner_message}</p>
                  </div>
                )}
              </div>
            )}

            {/* Inspected Code Context */}
            {validation.code_excerpt_inspected && (
              <div className="p-4 bg-white rounded-xl border border-slate-200/80 shadow-2xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Code2 className="w-4 h-4 text-slate-500" />
                    <h4 className="font-semibold text-xs uppercase tracking-wider text-slate-800">
                      Inspected Source Context
                    </h4>
                  </div>
                  <span className="text-[11px] text-slate-500">
                    {validation.context_start_line && validation.context_end_line
                      ? `Lines ${validation.context_start_line} – ${validation.context_end_line}`
                      : 'Bounded Snippet'}
                    {validation.is_context_truncated ? ' (Truncated)' : ''}
                  </span>
                </div>
                <div className="p-3.5 bg-slate-900 text-slate-200 rounded-lg font-mono text-xs overflow-x-auto leading-relaxed">
                  <pre className="whitespace-pre">{validation.code_excerpt_inspected}</pre>
                </div>
              </div>
            )}

            {/* Evidence Breakdown Grid: Supporting vs Refuting */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Supporting Evidence */}
              <div className="p-4 rounded-xl bg-emerald-50/40 border border-emerald-200/70 space-y-3">
                <div className="flex items-center gap-2 text-emerald-900">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  <h4 className="font-semibold text-xs uppercase tracking-wider">
                    Supporting Evidence ({(validation.supporting_evidence || []).length})
                  </h4>
                </div>

                {(!validation.supporting_evidence || validation.supporting_evidence.length === 0) ? (
                  <p className="text-xs text-slate-500 italic">No positive supporting evidence recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {validation.supporting_evidence.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-emerald-200 text-xs space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-semibold text-emerald-800">
                          <span className="uppercase">{item.evidence_type}</span>
                          {item.line_number && <span>Line {item.line_number}</span>}
                        </div>
                        <p className="text-slate-700">{item.description}</p>
                        {item.code_snippet && (
                          <div className="p-1.5 bg-slate-900 text-slate-100 rounded text-[11px] font-mono overflow-x-auto">
                            <code>{item.code_snippet}</code>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Refuting Evidence */}
              <div className="p-4 rounded-xl bg-amber-50/40 border border-amber-200/70 space-y-3">
                <div className="flex items-center gap-2 text-amber-900">
                  <XCircle className="w-4 h-4 text-amber-600" />
                  <h4 className="font-semibold text-xs uppercase tracking-wider">
                    Refuting Evidence / Mitigating Signals ({(validation.refuting_evidence || []).length})
                  </h4>
                </div>

                {(!validation.refuting_evidence || validation.refuting_evidence.length === 0) ? (
                  <p className="text-xs text-slate-500 italic">No refuting or mitigating signals recorded.</p>
                ) : (
                  <div className="space-y-2">
                    {validation.refuting_evidence.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-amber-200 text-xs space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-semibold text-amber-800">
                          <span className="uppercase">{item.evidence_type}</span>
                          {item.line_number && <span>Line {item.line_number}</span>}
                        </div>
                        <p className="text-slate-700">{item.description}</p>
                        {item.code_snippet && (
                          <div className="p-1.5 bg-slate-900 text-slate-100 rounded text-[11px] font-mono overflow-x-auto">
                            <code>{item.code_snippet}</code>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Missing Evidence Required */}
            <div className="p-4 rounded-xl bg-slate-50/70 border border-slate-200/80 space-y-2">
              <div className="flex items-center gap-2 text-slate-800">
                <HelpCircle className="w-4 h-4 text-slate-500" />
                <h4 className="font-semibold text-xs uppercase tracking-wider text-slate-700">
                  Evidence Required to Reach Stronger Conclusion
                </h4>
              </div>
              {(!validation.missing_evidence || validation.missing_evidence.length === 0) ? (
                <p className="text-xs text-slate-500 italic">No additional evidence required for the current classification.</p>
              ) : (
                <ul className="list-disc pl-5 text-xs text-slate-700 space-y-1">
                  {validation.missing_evidence.map((item, idx) => (
                    <li key={idx} className="leading-relaxed">{item}</li>
                  ))}
                </ul>
              )}
            </div>

            {/* Analysis Limitations */}
            {validation.analysis_limitations && validation.analysis_limitations.length > 0 && (
              <div className="p-4 rounded-xl bg-slate-50/70 border border-slate-200/80 space-y-2">
                <div className="flex items-center gap-2 text-slate-800">
                  <AlertTriangle className="w-4 h-4 text-amber-500" />
                  <h4 className="font-semibold text-xs uppercase tracking-wider text-slate-700">
                    Analysis Limitations &amp; Unsupported Capabilities
                  </h4>
                </div>
                <ul className="list-disc pl-5 text-xs text-slate-600 space-y-1">
                  {validation.analysis_limitations.map((limitation, idx) => (
                    <li key={idx} className="leading-relaxed">{limitation}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Suggested Next Steps */}
            {validation.suggested_next_steps && validation.suggested_next_steps.length > 0 && (
              <div className="p-4 rounded-xl bg-blue-50/40 border border-blue-200/70 space-y-2">
                <div className="flex items-center gap-2 text-blue-900">
                  <ArrowRight className="w-4 h-4 text-blue-600" />
                  <h4 className="font-semibold text-xs uppercase tracking-wider">
                    Suggested Next Steps
                  </h4>
                </div>
                <ul className="list-disc pl-5 text-xs text-blue-950 space-y-1">
                  {validation.suggested_next_steps.map((step, idx) => (
                    <li key={idx} className="leading-relaxed">{step}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* Evidence Hash Footer */}
            {validation.evidence_hash && (
              <div className="pt-2 border-t border-slate-200/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500">
                <div className="flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-slate-400" />
                  <span>Evidence SHA-256:</span>
                  <button
                    type="button"
                    onClick={() => setShowFullHash(!showFullHash)}
                    className="text-blue-600 hover:underline font-mono text-[11px] cursor-pointer"
                    title="Click to toggle full hash"
                  >
                    {showFullHash ? validation.evidence_hash : `${validation.evidence_hash.substring(0, 16)}...`}
                  </button>
                </div>
                <div>
                  <span>Recorded: {validation.recorded_at ? new Date(validation.recorded_at).toLocaleString() : 'N/A'}</span>
                </div>
              </div>
            )}
          </>
        )}

        {/* Empty state when finding is not yet validated */}
        {!validation && !isLoading && (
          <div className="py-8 px-4 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mx-auto text-slate-400">
              <Shield className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h4 className="font-semibold text-sm text-slate-900">
                No Evidence Validation Recorded
              </h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto leading-relaxed">
                Click <strong>Evaluate Evidence</strong> above to inspect the source file AST, data-flow patterns, and context boundaries to classify this scanner finding.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};