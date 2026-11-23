import React from 'react';
import {
  Sparkles,
  Lock,
  AlertTriangle,
  Info,
  CheckCircle2,
  AlertCircle,
  FileCheck,
  Loader2,
} from 'lucide-react';
import { AnalysisResult } from '../../services/api';

export interface AiSecurityAnalystCardProps {
  analysis: AnalysisResult | null;
  isLoading: boolean;
  error: string | null;
  userAuthorized: boolean;
  onToggleAuthorization: (authorized: boolean) => void;
  onRunAnalysis: () => void;
}

export const AiSecurityAnalystCard: React.FC<AiSecurityAnalystCardProps> = ({
  analysis,
  isLoading,
  error,
  userAuthorized,
  onToggleAuthorization,
  onRunAnalysis,
}) => {
  return (
    <div className="rounded-xl bg-white border border-slate-200/80 shadow-2xs overflow-hidden font-sans">
      {/* Header Banner */}
      <div className="bg-slate-50 border-b border-slate-200/80 px-5 py-3.5 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-50 text-blue-600 border border-blue-100">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h4 className="font-semibold text-xs text-slate-900">
                AI-Generated Security Analysis — Requires Human Review
              </h4>
              {analysis?.ai_model && analysis.ai_model.toLowerCase().includes('fallback') && (
                <span className="px-2 py-0.5 rounded-full bg-amber-50 text-amber-800 border border-amber-200 text-[10px] font-semibold">
                  Offline Deterministic Engine
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-500">
              Remediation insights and root cause claims must be validated by security engineers prior to implementation.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={userAuthorized}
              onChange={(e) => onToggleAuthorization(e.target.checked)}
              className="rounded border-slate-300 text-slate-900 focus:ring-slate-900 w-3.5 h-3.5 cursor-pointer"
            />
            <span className="font-medium text-xs text-slate-700">Authorize Code Analysis</span>
          </label>
          <button
            type="button"
            onClick={onRunAnalysis}
            disabled={!userAuthorized || isLoading}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors cursor-pointer ${
              !userAuthorized || isLoading
                ? 'bg-slate-100 text-slate-400 cursor-not-allowed'
                : 'bg-slate-900 text-white hover:bg-slate-800 shadow-xs'
            }`}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Generate Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Loading State */}
        {isLoading && (
          <div className="py-8 flex flex-col items-center justify-center space-y-2.5">
            <Loader2 className="w-6 h-6 text-slate-900 animate-spin" />
            <p className="text-xs text-slate-600 font-medium">
              Synthesizing AI Security Assessment...
            </p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-lg text-rose-800 text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold mr-1">Analyst Service Notice:</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {/* Authorization Hold State */}
        {!userAuthorized && !isLoading && (
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-slate-700 text-xs flex items-start gap-3">
            <div className="p-1.5 rounded-md bg-slate-200/70 text-slate-600 shrink-0 mt-0.5">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <p className="font-semibold text-slate-800">
                Authorization Hold: Opt-in required
              </p>
              <p className="text-slate-600 mt-0.5 leading-relaxed">
                To safeguard intellectual property, private repository content will not be sent to external language models without explicit administrator authorization.
              </p>
            </div>
          </div>
        )}

        {/* Analysis Details */}
        {analysis && !isLoading && (
          <div className="space-y-4">
            {/* Meta bar */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-800 text-xs font-medium border border-slate-200">
                  {analysis.ai_model}
                </span>
                <span className="px-2 py-0.5 rounded bg-blue-50 text-blue-700 text-xs font-medium border border-blue-100">
                  {analysis.confidence}
                </span>
              </div>
              <div>
                {analysis.is_exploitable_claim_supported ? (
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-medium flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Exploitability Supported by Static Flow</span>
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded-full bg-amber-50 text-amber-700 border border-amber-200 text-xs font-medium flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                    <span>Exploitability Unproven / Context Incomplete</span>
                  </span>
                )}
              </div>
            </div>

            {/* Explanation & Root cause */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3.5 bg-slate-50/70 rounded-lg border border-slate-200/80">
                <h5 className="font-semibold text-xs uppercase tracking-wider text-slate-600 mb-1.5">
                  Vulnerability Summary
                </h5>
                <p className="text-xs text-slate-800 leading-relaxed">
                  {analysis.plain_language_explanation}
                </p>
              </div>

              <div className="p-3.5 bg-slate-50/70 rounded-lg border border-slate-200/80">
                <h5 className="font-semibold text-xs uppercase tracking-wider text-slate-600 mb-1.5">
                  Root Cause Analysis
                </h5>
                <p className="text-xs text-slate-800 leading-relaxed">
                  {analysis.likely_root_cause}
                </p>
              </div>
            </div>

            {/* Potential Impact */}
            <div className="p-3.5 bg-rose-50/40 rounded-lg border border-rose-200/60">
              <h5 className="font-semibold text-xs uppercase tracking-wider text-rose-800 mb-1.5">
                Security Impact
              </h5>
              <p className="text-xs text-rose-900 leading-relaxed">
                {analysis.potential_impact}
              </p>
            </div>

            {/* Remediation & Targeted Tests */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-3.5 bg-slate-50/70 rounded-lg border border-slate-200/80">
                <h5 className="font-semibold text-xs uppercase tracking-wider text-slate-700 mb-2">
                  Recommended Remediation
                </h5>
                <ul className="space-y-1.5 list-disc pl-4 text-xs text-slate-700">
                  {(analysis.suggested_remediation || analysis.recommended_remediation || []).map((item, idx) => (
                    <li key={idx} className="leading-relaxed">{item}</li>
                  ))}
                </ul>
              </div>

              <div className="p-3.5 bg-slate-50/70 rounded-lg border border-slate-200/80">
                <h5 className="font-semibold text-xs uppercase tracking-wider text-slate-700 mb-2">
                  Recommended Test Cases
                </h5>
                <ul className="space-y-1.5 list-disc pl-4 text-xs text-slate-700">
                  {(analysis.suggested_targeted_tests || analysis.suggested_tests || []).map((item, idx) => (
                    <li key={idx} className="leading-relaxed">{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Caveats & Limitations */}
            {((analysis.missing_context && analysis.missing_context.length > 0) || (analysis.limitations && analysis.limitations.length > 0)) && (
              <div className="pt-2 border-t border-slate-100 text-xs space-y-1 text-slate-600">
                {(analysis.missing_context || []).map((ctx, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 text-[11px] text-slate-500">
                    <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    <span>{ctx}</span>
                  </div>
                ))}
                {(analysis.limitations || []).map((lim, idx) => (
                  <div key={idx} className="flex items-center gap-1.5 text-[11px] text-slate-500">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                    <span>{lim}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Empty State when no analysis generated yet */}
        {!analysis && !isLoading && !error && userAuthorized && (
          <div className="py-8 flex flex-col items-center justify-center text-center space-y-2">
            <div className="p-2.5 rounded-full bg-slate-100 text-slate-400 mb-1">
              <FileCheck className="w-6 h-6" />
            </div>
            <p className="font-semibold text-xs text-slate-800">No Analysis Generated Yet</p>
            <p className="text-xs text-slate-500 max-w-sm">
              Click &quot;Generate Analysis&quot; above to inspect root causes, exploitability factors, and candidate fixes.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};