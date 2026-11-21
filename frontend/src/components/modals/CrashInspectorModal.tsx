import React from 'react';
import { AlertTriangle, X, RotateCw, Terminal } from 'lucide-react';
import { VerificationItem } from '../../types';

interface CrashInspectorModalProps {
  item: VerificationItem | null;
  onClose: () => void;
  onRerun: (id: string) => void;
  isRerunning?: boolean;
}

export const CrashInspectorModal: React.FC<CrashInspectorModalProps> = ({
  item,
  onClose,
  onRerun,
  isRerunning,
}) => {
  if (!item) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 font-sans backdrop-blur-2xs">
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl border border-slate-200 flex flex-col max-h-[85vh] overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div
              className={`w-9 h-9 rounded-lg flex items-center justify-center text-white ${
                item.status === 'failed' ? 'bg-rose-600' : 'bg-amber-600'
              }`}
            >
              <AlertTriangle className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">
                  {item.status === 'failed'
                    ? 'Verification Failure Details'
                    : 'Verification Diagnostic'}
                </h3>
                {item.prNumber && (
                  <span className="px-2 py-0.5 rounded-md bg-rose-50 text-rose-700 font-mono text-xs font-bold border border-rose-200">
                    PR #{item.prNumber}
                  </span>
                )}
              </div>
              <p className="font-mono text-xs text-slate-500 mt-0.5">
                Target: <span className="font-semibold text-slate-800">{item.repo}</span> • Branch:{' '}
                <span className="font-medium text-slate-800">{item.branch}</span>
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {/* Reason Alert Box */}
          <div className="p-4 rounded-xl bg-rose-50 border border-rose-200 text-xs">
            <div className="flex items-center gap-2 font-bold text-rose-800 mb-1">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
              <span>Verification Failed — Pull Request Blocked</span>
            </div>
            <p className="font-mono text-slate-800 leading-relaxed text-xs">
              {item.crashReason || item.message}
            </p>
          </div>

          {/* Test Harness Status */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block">
                Test Suite Result
              </span>
              <span className="font-mono text-xs font-bold text-rose-700 mt-1 block">
                {item.unitTestsPassRate || 'Tests Failed'}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-[10px] font-mono text-slate-500 uppercase font-semibold block">
                Execution Duration
              </span>
              <span className="font-mono text-xs font-bold text-slate-800 mt-1 block">
                {item.executionTime}
              </span>
            </div>
          </div>

          {/* Real Sandbox Terminal Logs */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
                Sandbox Execution Logs
              </span>
              <span className="font-mono text-xs text-slate-400">Environment: Isolated Sandbox</span>
            </div>
            <div className="p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs space-y-1.5 overflow-x-auto max-h-56 shadow-inner">
              {item.crashLogs && item.crashLogs.length > 0 ? (
                item.crashLogs.map((log, idx) => (
                  <div
                    key={idx}
                    className={`leading-relaxed ${
                      log.includes('FAIL') ||
                      log.includes('error') ||
                      log.includes('QUARANTINE') ||
                      log.includes('[ERROR]')
                        ? 'text-rose-400 font-semibold'
                        : 'text-slate-300'
                    }`}
                  >
                    {log}
                  </div>
                ))
              ) : (
                <div className="text-slate-400">
                  [runner] Verification execution failed. Check CI logs above.
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between gap-3">
          <span className="text-xs text-slate-500">
            Pull request cannot merge until all regression checks pass.
          </span>
          <div className="flex items-center gap-2.5">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors shadow-2xs cursor-pointer"
            >
              Close
            </button>
            <button
              disabled={isRerunning}
              onClick={() => onRerun(item.id)}
              className="flex items-center gap-1.5 px-4 py-2 rounded-md bg-slate-900 text-white hover:bg-slate-800 text-xs font-medium transition-colors shadow-2xs disabled:opacity-50 cursor-pointer"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isRerunning ? 'animate-spin' : ''}`} />
              <span>{isRerunning ? 'Rerunning in Sandbox...' : 'Rerun Verification'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
