import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  X,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Check,
  Shield,
  Layers,
  Sparkles,
} from 'lucide-react';
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
    title: 'Verified Fix (Recommended)',
    description: 'Applies safe parameterized queries and input validation.',
    expectedVerdict: 'VERIFIED_AGAINST_DEFINED_CHECKS',
  },
  INEFFECTIVE_FIX: {
    label: 'Preset 2: Ineffective Sanitization (Persisting)',
    title: 'Simulate Incomplete Fix',
    description: 'Tests if sandbox catches unescaped edge cases.',
    expectedVerdict: 'FAILED_VERIFICATION',
  },
  REGRESSION_FIX: {
    label: 'Preset 3: Introduces Regression Finding',
    title: 'Simulate Regression Bug',
    description: 'Tests if sandbox catches new vulnerability side-effects.',
    expectedVerdict: 'FAILED_VERIFICATION',
  },
  PATH_TRAVERSAL: {
    label: 'Preset 4: Malicious Path Traversal Attempt',
    title: 'Simulate Path Traversal',
    description: 'Tests sandbox defense against illegal directory access.',
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

  if (normPath.includes('security.py') || normPath.includes('config') || normPath.includes('.env')) {
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
  const [activePreset, setActivePreset] = useState<keyof typeof PRESET_PATCHES>('VALID_FIX');
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
      setPatchDiff(generateDiffForFinding(activePreset, found.file_path, found.line_number));
      setValidationResult(null);
      setValidationError(null);
    }
  };

  const handleApplyPreset = (key: keyof typeof PRESET_PATCHES) => {
    setActivePreset(key);
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs overflow-y-auto font-sans animate-in fade-in duration-100">
      <div className="relative w-full max-w-2xl bg-white rounded-2xl shadow-2xl border border-slate-200 my-8 overflow-hidden animate-in zoom-in-95 duration-150 flex flex-col max-h-[90vh]">
        
        {/* Header - Clean Monochromatic */}
        <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shrink-0">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-slate-900">
                Trigger Fix Verification Engine
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Test and verify the security fix in an isolated sandbox before applying it.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <div className="p-6 space-y-4 overflow-y-auto">
          {/* Target Finding Selection */}
          <div>
            <label className="text-xs font-semibold text-slate-700 block mb-1">
              Target Security Finding {openFindings.length > 0 ? `(${openFindings.length} Available)` : ''}
            </label>
            {openFindings.length > 0 ? (
              <select
                value={findingId}
                onChange={e => handleSelectFinding(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-lg focus:bg-white focus:border-slate-400 focus:outline-hidden text-slate-900 font-medium"
              >
                {openFindings.map(f => (
                  <option key={f.id} value={f.id}>
                    [{f.severity}] {f.title} — {f.file_path}:{f.line_number}
                  </option>
                ))}
              </select>
            ) : (
              <div className="px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-700 flex items-center justify-between">
                <span className="font-mono text-slate-800">Finding: {findingId || 'Active security issue'}</span>
                <span className="text-[11px] text-slate-500">Selected</span>
              </div>
            )}
            {selectedFinding && (
              <div className="mt-1.5 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-600 flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <FileCode className="w-3.5 h-3.5 text-slate-400" />
                  <span>Target: <strong className="text-slate-900">{selectedFinding.file_path}:{selectedFinding.line_number}</strong></span>
                </span>
                <span className="text-[11px] text-slate-500 font-mono">{selectedFinding.cwe}</span>
              </div>
            )}
          </div>

          {/* Test Scenarios - Clean Monochromatic Cards */}
          <div className="space-y-1.5">
            <span className="text-xs font-semibold text-slate-700 block">
              Remediation Test Scenarios
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {(Object.keys(PRESET_PATCHES) as Array<keyof typeof PRESET_PATCHES>).map(key => {
                const preset = PRESET_PATCHES[key];
                const isActive = activePreset === key;

                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleApplyPreset(key)}
                    className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                      isActive
                        ? 'border-slate-900 bg-slate-50/70 shadow-2xs ring-1 ring-slate-900'
                        : 'border-slate-200 bg-white hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-semibold text-xs text-slate-900">
                        {preset.label}
                      </span>
                      {isActive && <Check className="w-3.5 h-3.5 text-slate-900 shrink-0" />}
                    </div>
                    <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                      {preset.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Proposed Patch Diff Textarea */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-700">
                Proposed Patch (Unified Diff)
              </label>
              <button
                type="button"
                onClick={handleValidatePatch}
                disabled={isValidating || !patchDiff.trim()}
                className="px-2.5 py-1 text-xs font-medium rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer shadow-2xs disabled:opacity-50"
              >
                <Shield className="w-3 h-3 text-slate-500" />
                <span>{isValidating ? 'Validating...' : 'Validate Patch Safely'}</span>
              </button>
            </div>
            <textarea
              rows={6}
              value={patchDiff}
              onChange={e => {
                setPatchDiff(e.target.value);
                setValidationResult(null);
              }}
              className="w-full px-3 py-2.5 font-mono text-xs bg-slate-900 text-slate-100 border border-slate-800 rounded-xl focus:border-slate-400 focus:outline-hidden shadow-inner leading-relaxed"
              placeholder="--- a/path/to/file.py&#10;+++ b/path/to/file.py&#10;@@ -1,3 +1,3 @@"
            />
          </div>

          {/* Patch Validation Results */}
          {validationResult && (
            <div className="p-3 rounded-xl border border-slate-200 bg-slate-50 text-xs text-slate-800 space-y-1">
              <div className="flex items-center justify-between font-semibold">
                <span className="flex items-center gap-1.5 text-slate-900">
                  <CheckCircle2 className="w-4 h-4 text-slate-800" />
                  <span>Patch Parsing &amp; Path Validation Passed</span>
                </span>
                <span className="font-mono text-[11px] text-slate-600">
                  +{validationResult.total_added} / -{validationResult.total_deleted} lines
                </span>
              </div>
              {validationResult.errors.length > 0 && (
                <div className="mt-1 text-rose-700 text-[11px] space-y-0.5">
                  {validationResult.errors.map((err, i) => (
                    <div key={i}>• {err}</div>
                  ))}
                </div>
              )}
              {validationResult.files.length > 0 && (
                <div className="pt-1.5 border-t border-slate-200 text-[11px] text-slate-600 space-y-0.5">
                  {validationResult.files.map((f, i) => (
                    <div key={i}>
                      Touched: <strong className="font-mono text-slate-800">{f.new_path}</strong> ({f.modified_lines_range})
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {validationError && (
            <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-700 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{validationError}</span>
            </div>
          )}

          {/* Verification Checks Options */}
          <div className="space-y-1.5 pt-1">
            <span className="text-xs font-semibold text-slate-700 block">
              Defined Security Verification Gates
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
              <label className="flex items-center gap-2 p-2.5 rounded-xl bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100/60 transition-colors">
                <input
                  type="checkbox"
                  checked={runScanners}
                  onChange={e => setRunScanners(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span className="font-medium text-slate-800">Static Scanners</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-xl bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100/60 transition-colors">
                <input
                  type="checkbox"
                  checked={runExistingTests}
                  onChange={e => setRunExistingTests(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span className="font-medium text-slate-800">Unit Test Suite</span>
              </label>

              <label className="flex items-center gap-2 p-2.5 rounded-xl bg-slate-50 border border-slate-200 cursor-pointer hover:bg-slate-100/60 transition-colors">
                <input
                  type="checkbox"
                  checked={runRegressionTests}
                  onChange={e => setRunRegressionTests(e.target.checked)}
                  className="rounded border-slate-300 accent-slate-900"
                />
                <span className="font-medium text-slate-800">Regression Tests</span>
              </label>
            </div>
          </div>

          {executionError && (
            <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-700 text-xs flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <span>{executionError}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-slate-100 flex items-center justify-between shrink-0">
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 border border-slate-200 rounded-lg text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors cursor-pointer"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleExecute}
            disabled={isExecuting || !patchDiff.trim()}
            className="px-4 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-xs transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>{isExecuting ? 'Executing In Sandbox...' : 'Run Fix Verification'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
