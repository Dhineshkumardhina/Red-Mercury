import React, { useState, useEffect } from 'react';
import { api, PatchValidationResponse, ApiVerificationRun, ApiFinding } from '../../services/api';

interface NewVerificationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (run: ApiVerificationRun) => void;
  initialFindingId?: string;
  initialDiff?: string;
}

const PRESET_PATCHES = {
  VALID_FIX: {
    label: 'Preset 1: Valid Remediation Fix',
    expectedVerdict: 'VERIFIED_AGAINST_DEFINED_CHECKS',
  },
  INEFFECTIVE_FIX: {
    label: 'Preset 2: Ineffective Sanitization (Persisting)',
    expectedVerdict: 'FAILED_VERIFICATION',
  },
  REGRESSION_FIX: {
    label: 'Preset 3: Introduces Regression Finding',
    expectedVerdict: 'FAILED_VERIFICATION',
  },
  PATH_TRAVERSAL: {
    label: 'Preset 4: Malicious Path Traversal Attempt',
    expectedVerdict: 'REJECTED (INCONCLUSIVE)',
  },
};

function generateDiffForFinding(
  presetKey: keyof typeof PRESET_PATCHES,
  filePath: string,
  lineNumber: number = 10
): string {
  const normPath = filePath.replace(/\\/g, '/');
  const line = Math.max(1, lineNumber);

  if (presetKey === 'PATH_TRAVERSAL') {
    return `--- a/../../../../etc/shadow
+++ b/../../../../etc/shadow
@@ -1,1 +1,1 @@
-root:*
+root:pwned`;
  }

  if (presetKey === 'INEFFECTIVE_FIX') {
    return `--- a/${normPath}
+++ b/${normPath}
@@ -${line},3 +${line},3 @@
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    sanitized = str(user_id).replace("'", "")
+    query = f"SELECT * FROM users WHERE id = '{sanitized}'"`;
  }

  if (presetKey === 'REGRESSION_FIX') {
    return `--- a/${normPath}
+++ b/${normPath}
@@ -${line},3 +${line},4 @@
+    import os
+    os.system(f"echo Processing request for {user_id}")
     query = "SELECT * FROM users WHERE id = %s"
     cursor.execute(query, (user_id,))`;
  }

  // VALID_FIX default
  if (normPath.includes('main.py') || normPath.includes('server')) {
    return `--- a/${normPath}
+++ b/${normPath}
@@ -${line},3 +${line},3 @@
-    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
+    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)`;
  }

  if (normPath.includes('security.py') || normPath.includes('config')) {
    return `--- a/${normPath}
+++ b/${normPath}
@@ -${line},3 +${line},3 @@
-    SECRET_KEY = "dev-insecure-secret-key-32-chars-long!!"
+    SECRET_KEY = os.getenv("APP_SECRET_KEY", "default-fallback-for-tests-only")`;
  }

  return `--- a/${normPath}
+++ b/${normPath}
@@ -${line},3 +${line},3 @@
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    query = "SELECT * FROM users WHERE id = %s"
+    cursor.execute(query, (user_id,))`;
}

const DEFAULT_INITIAL_DIFF = `--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -10,7 +10,7 @@
     # Secure implementation using parameterized query binding
-    query = f"SELECT id, username, email FROM users WHERE tenant_id = '{tenant_id}'"
-    cursor.execute(query)
+    query = "SELECT id, username, email FROM users WHERE tenant_id = %s"
+    cursor.execute(query, (tenant_id,))
     return cursor.fetchall()`;

export const NewVerificationModal: React.FC<NewVerificationModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  initialFindingId,
  initialDiff,
}) => {
  const [openFindings, setOpenFindings] = useState<ApiFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<ApiFinding | null>(null);
  const [findingId, setFindingId] = useState<string>(initialFindingId || '');
  const [patchDiff, setPatchDiff] = useState<string>(initialDiff || DEFAULT_INITIAL_DIFF);
  const [runScanners, setRunScanners] = useState(true);
  const [runExistingTests, setRunExistingTests] = useState(true);
  const [runRegressionTests, setRunRegressionTests] = useState(true);

  const [validationResult, setValidationResult] = useState<PatchValidationResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const [isExecuting, setIsExecuting] = useState(false);
  const [executionError, setExecutionError] = useState<string | null>(null);

  // Load real findings from database on mount or open
  useEffect(() => {
    if (!isOpen) return;

    let mounted = true;
    api.getFindings({ status: 'open' })
      .then(res => {
        if (!mounted) return;
        const findings = Array.isArray(res) ? res : [];
        setOpenFindings(findings);

        if (initialFindingId) {
          const match = findings.find(f => f.id === initialFindingId);
          if (match) {
            setSelectedFinding(match);
            setFindingId(match.id);
            if (!initialDiff) {
              setPatchDiff(generateDiffForFinding('VALID_FIX', match.file_path, match.line_number));
            }
            return;
          }
        }

        if (findings.length > 0 && !findingId) {
          const first = findings[0];
          setSelectedFinding(first);
          setFindingId(first.id);
          if (!patchDiff) {
            setPatchDiff(generateDiffForFinding('VALID_FIX', first.file_path, first.line_number));
          }
        }
      })
      .catch(() => {});

    return () => {
      mounted = false;
    };
  }, [isOpen, initialFindingId]);

  if (!isOpen) return null;

  const handleSelectFinding = (id: string) => {
    setFindingId(id);
    const found = openFindings.find(f => f.id === id);
    if (found) {
      setSelectedFinding(found);
      setPatchDiff(generateDiffForFinding('VALID_FIX', found.file_path, found.line_number));
      setValidationResult(null);
      setValidationError(null);
    }
  };

  const handleApplyPreset = (key: keyof typeof PRESET_PATCHES) => {
    const filePath = selectedFinding?.file_path || 'backend/app/main.py';
    const line = selectedFinding?.line_number || 10;
    const diff = generateDiffForFinding(key, filePath, line);
    setPatchDiff(diff);
    setValidationResult(null);
    setValidationError(null);
  };

  const handleValidatePatch = async () => {
    setIsValidating(true);
    setValidationError(null);
    try {
      const res = await api.validatePatch(patchDiff);
      setValidationResult(res);
    } catch (err: any) {
      setValidationError(err.message || 'Patch validation failed.');
      setValidationResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const handleExecute = async () => {
    if (!findingId.trim()) {
      setExecutionError('Please select or specify a target finding identifier.');
      return;
    }
    if (!patchDiff.trim()) {
      setExecutionError('Proposed unified patch diff cannot be empty.');
      return;
    }

    setIsExecuting(true);
    setExecutionError(null);
    try {
      const res = await api.triggerVerification({
        finding_id: findingId,
        proposed_patch: patchDiff,
        run_existing_tests: runExistingTests,
        run_regression_tests: runRegressionTests,
      });
      onSuccess(res);
      onClose();
    } catch (err: any) {
      setExecutionError(err.message || 'Fix Verification execution failed.');
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 overflow-y-auto font-sans">
      <div className="relative w-full max-w-3xl bg-white rounded-xl shadow-2xl border border-slate-200 my-8 overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <span className="material-symbols-outlined text-xl">play_arrow</span>
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Trigger Fix Verification Engine
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Evaluate proposed patch in isolated sandbox workspace against defined security gates
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <span className="material-symbols-outlined text-xl">close</span>
          </button>
        </div>

        {/* Form Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {/* Real Findings Dropdown */}
          <div>
            <label className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider block mb-1.5">
              Target Security Finding ({openFindings.length} Available)
            </label>
            {openFindings.length > 0 ? (
              <select
                value={findingId}
                onChange={e => handleSelectFinding(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-white border border-slate-200 rounded-lg focus:border-slate-400 focus:outline-hidden text-slate-800 font-medium"
              >
                {openFindings.map(f => (
                  <option key={f.id} value={f.id}>
                    [{f.severity}] {f.title} — {f.file_path}:{f.line_number} ({f.cwe || f.scanner_name})
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={findingId}
                onChange={e => setFindingId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-white border border-slate-200 rounded-lg focus:border-slate-400 focus:outline-hidden"
                placeholder="Enter Finding UUID"
              />
            )}
            {selectedFinding && (
              <div className="mt-1.5 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 flex items-center justify-between">
                <span>File: <strong className="text-slate-900">{selectedFinding.file_path}:{selectedFinding.line_number}</strong></span>
                <span className="text-[11px] text-slate-500 font-mono">ID: {selectedFinding.id.slice(0, 8)}...</span>
              </div>
            )}
          </div>

          {/* Controlled Preset Quick Select */}
          <div className="space-y-2">
            <span className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider block">
              Remediation Test Scenarios
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(Object.keys(PRESET_PATCHES) as Array<keyof typeof PRESET_PATCHES>).map(key => {
                const preset = PRESET_PATCHES[key];
                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleApplyPreset(key)}
                    className="p-2.5 rounded-lg border border-slate-200 text-left hover:border-slate-400 hover:bg-slate-50 transition-colors text-xs cursor-pointer"
                  >
                    <div className="font-semibold text-slate-800">{preset.label}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Expected Verdict: <span className="font-semibold text-slate-800">{preset.expectedVerdict}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Proposed Patch Diff Textarea */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider">
                Proposed Patch (Unified Diff)
              </label>
              <button
                type="button"
                onClick={handleValidatePatch}
                disabled={isValidating || !patchDiff.trim()}
                className="px-2.5 py-1 text-xs font-semibold rounded bg-slate-100 hover:bg-slate-200 text-slate-700 flex items-center gap-1 transition-colors border border-slate-200 cursor-pointer"
              >
                <span className="material-symbols-outlined text-xs">rule</span>
                {isValidating ? 'Validating...' : 'Validate Patch Safely'}
              </button>
            </div>
            <textarea
              rows={8}
              value={patchDiff}
              onChange={e => {
                setPatchDiff(e.target.value);
                setValidationResult(null);
              }}
              className="w-full px-3 py-2 font-mono text-xs bg-slate-900 text-emerald-400 border border-slate-700 rounded-lg focus:border-slate-400 focus:outline-hidden shadow-inner"
              placeholder="--- a/path/to/file.py&#10;+++ b/path/to/file.py&#10;@@ -1,3 +1,3 @@"
            />
          </div>

          {/* Patch Validation Results */}
          {validationResult && (
            <div className={`p-4 rounded-xl border text-xs ${
              validationResult.is_valid
                ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                : 'bg-rose-50 border-rose-200 text-rose-900'
            }`}>
              <div className="flex items-center justify-between font-bold mb-1">
                <span className="flex items-center gap-1">
                  <span className="material-symbols-outlined text-sm">
                    {validationResult.is_valid ? 'check_circle' : 'block'}
                  </span>
                  {validationResult.is_valid ? 'Patch Parsing & Path Validation Passed' : 'Diff Rejected'}
                </span>
                <span className="font-sans text-[11px] font-semibold">
                  +{validationResult.total_added} / -{validationResult.total_deleted} lines
                </span>
              </div>
              {validationResult.errors.length > 0 && (
                <div className="mt-1 text-rose-800 text-[11px] space-y-0.5">
                  {validationResult.errors.map((err, i) => (
                    <div key={i}>• {err}</div>
                  ))}
                </div>
              )}
              {validationResult.files.length > 0 && (
                <div className="mt-2 pt-2 border-t border-emerald-200/60 text-[11px] text-emerald-800 space-y-1">
                  {validationResult.files.map((f, i) => (
                    <div key={i}>
                      Touched: <strong className="font-mono">{f.new_path}</strong> ({f.modified_lines_range})
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {validationError && (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-xs">
              {validationError}
            </div>
          )}

          {/* Verification Checks Options */}
          <div className="space-y-2 pt-2 border-t border-slate-200">
            <span className="text-[11px] font-semibold text-slate-700 uppercase tracking-wider block">
              Defined Security Verification Gates
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runScanners}
                  onChange={e => setRunScanners(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Static Scanners</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runExistingTests}
                  onChange={e => setRunExistingTests(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Unit Test Suite</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100 transition-colors">
                <input
                  type="checkbox"
                  checked={runRegressionTests}
                  onChange={e => setRunRegressionTests(e.target.checked)}
                  className="rounded text-slate-900"
                />
                <span className="font-medium text-slate-800">Regression Tests</span>
              </label>
            </div>
          </div>

          {executionError && (
            <div className="p-3.5 bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-xs">
              {executionError}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-50 border-t border-slate-200 flex items-center justify-between">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-slate-600 hover:text-slate-800 cursor-pointer"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleExecute}
            disabled={isExecuting || !patchDiff.trim()}
            className={`px-5 py-2 rounded-lg text-xs font-bold text-white shadow-2xs transition-all flex items-center gap-2 cursor-pointer ${
              isExecuting || !patchDiff.trim()
                ? 'bg-slate-400 cursor-not-allowed'
                : 'bg-slate-900 hover:bg-slate-800'
            }`}
          >
            <span className="material-symbols-outlined text-sm">
              {isExecuting ? 'sync' : 'verified_user'}
            </span>
            {isExecuting ? 'Executing In Sandbox...' : 'Run Fix Verification'}
          </button>
        </div>
      </div>
    </div>
  );
};
