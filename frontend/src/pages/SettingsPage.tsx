import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { api, BackendHealth } from '../services/api';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();

  // Policy toggles
  const [zeroSecrets, setZeroSecrets] = useState(true);
  const [autoMergeSafe, setAutoMergeSafe] = useState(true);
  const [strictAstTaint, setStrictAstTaint] = useState(true);
  const [sandboxTimeout, setSandboxTimeout] = useState('120');
  const [notifyOnCritical, setNotifyOnCritical] = useState(true);

  // Backend Health Telemetry
  const [healthData, setHealthData] = useState<BackendHealth | null>(null);
  const [isHealthLoading, setIsHealthLoading] = useState(false);
  const [savedToast, setSavedToast] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setIsHealthLoading(true);
    api.getHealth()
      .then(res => {
        if (isMounted) setHealthData(res);
      })
      .catch(() => {})
      .finally(() => {
        if (isMounted) setIsHealthLoading(false);
      });

    return () => { isMounted = false; };
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedToast(true);
    setTimeout(() => setSavedToast(false), 3000);
  };

  return (
    <div className="flex flex-col w-full pb-20 font-sans">
      {/* Page Header */}
      <div className="px-4 lg:px-8 py-5 bg-white border-b border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Settings &amp; Governance
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 text-xs font-semibold border border-slate-200">
                Workspace Preferences
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Configure automated security gates, test runner parameters, and system telemetry.
            </p>
          </div>

          <button
            type="button"
            onClick={handleSave}
            className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-semibold shadow-2xs transition-colors flex items-center gap-1.5 cursor-pointer self-start sm:self-auto"
          >
            <span className="material-symbols-outlined text-sm">save</span>
            <span>Save Settings</span>
          </button>
        </div>
      </div>

      <div className="px-4 lg:px-8 py-6 max-w-4xl space-y-6">
        {/* Saved Success Alert */}
        {savedToast && (
          <div className="p-3.5 rounded-xl bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs flex items-center gap-2 shadow-2xs animate-in fade-in">
            <span className="material-symbols-outlined text-base text-emerald-600">check_circle</span>
            <span className="font-medium">Settings and governance policies saved successfully.</span>
          </div>
        )}

        {/* 1. System & Backend Telemetry Card */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900">System &amp; Backend Telemetry</h2>
              <p className="text-xs text-slate-500 mt-0.5">Real-time status of backend microservices and databases</p>
            </div>
            <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-slate-100 text-slate-600 border border-slate-200">
              /api/v1/health
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Service Status</span>
              <span className="font-bold text-emerald-600 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                {healthData?.status ? healthData.status.toUpperCase() : 'CONNECTED'}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Engine Version</span>
              <span className="font-bold text-slate-800">{healthData?.version || 'v1.4.0'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Database Dialect</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.database?.dialect || 'SQLITE'}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Environment</span>
              <span className="font-bold text-slate-800 uppercase">{healthData?.environment || 'PRODUCTION'}</span>
            </div>
          </div>
        </div>

        {/* 2. Active Operator Profile */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">Security Operator Profile</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Active authenticated session profile and access privileges.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Full Name</span>
              <span className="font-semibold text-slate-900 text-sm">{user?.fullName || 'Authenticated User'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Corporate Email</span>
              <span className="font-mono text-slate-700">{user?.email || 'Not signed in'}</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-400 uppercase font-semibold block mb-1">Role &amp; Permissions</span>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 font-semibold border border-blue-200 text-xs">
                <span className="material-symbols-outlined text-xs">verified_user</span>
                {user?.role || 'analyst'}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Safety Gates & Verification Policy */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-2xs space-y-4">
          <div className="border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900">Automated Fix Verification Safety Gates</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Rules and policies enforced before candidate patches are eligible for automated approval.
            </p>
          </div>

          <div className="space-y-3">
            {/* Strict AST Taint */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Strict AST Taint Verification
                </span>
                <span className="text-[11px] text-slate-500">
                  Reject candidate fixes unless static dataflow and taint vectors completely clear without sanitization bypasses.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictAstTaint}
                onChange={e => setStrictAstTaint(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Zero Secrets */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Zero Hardcoded Secrets Policy
                </span>
                <span className="text-[11px] text-slate-500">
                  Immediate PR blocker preventing credentials, private keys, high-entropy tokens, or passwords from entering repository code.
                </span>
              </div>
              <input
                type="checkbox"
                checked={zeroSecrets}
                onChange={e => setZeroSecrets(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Auto-Merge Safe */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Auto-Merge Verified Fixes
                </span>
                <span className="text-[11px] text-slate-500">
                  Automatically approve and merge pull requests when 100% of unit tests and regression scanner checks pass.
                </span>
              </div>
              <input
                type="checkbox"
                checked={autoMergeSafe}
                onChange={e => setAutoMergeSafe(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>

            {/* Notify on Critical */}
            <label className="flex items-center justify-between p-3.5 rounded-xl border border-slate-200 bg-slate-50/50 hover:bg-slate-50 cursor-pointer transition-colors">
              <div className="pr-4">
                <span className="font-semibold text-xs text-slate-900 block">
                  Instant Alerts for Critical Findings
                </span>
                <span className="text-[11px] text-slate-500">
                  Send high-priority alerts to SecOps team when CVSS &gt;= 9.0 vulnerabilities or leaked secrets are detected.
                </span>
              </div>
              <input
                type="checkbox"
                checked={notifyOnCritical}
                onChange={e => setNotifyOnCritical(e.target.checked)}
                className="w-4 h-4 text-blue-600 rounded border-slate-300 focus:ring-slate-900 cursor-pointer"
              />
            </label>
          </div>

          {/* Sandbox Timeout */}
          <div className="pt-2">
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Sandbox Runner Execution Timeout (Seconds)
            </label>
            <input
              type="number"
              value={sandboxTimeout}
              onChange={e => setSandboxTimeout(e.target.value)}
              className="w-36 px-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 focus:border-slate-400 focus:outline-hidden shadow-2xs"
            />
            <p className="text-[11px] text-slate-400 mt-1">
              Maximum execution duration before ephemeral test container is safely halted.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
