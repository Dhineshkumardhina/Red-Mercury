import React, { useState } from 'react';
import { Download, X, CheckCircle2 } from 'lucide-react';
import { ApiFinding, ApiRepository } from '../../services/api';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  findings?: ApiFinding[];
  repositories?: ApiRepository[];
}

export const ExportModal: React.FC<ExportModalProps> = ({
  isOpen,
  onClose,
  findings = [],
  repositories = [],
}) => {
  const [format, setFormat] = useState<'sarif' | 'json' | 'summary'>('sarif');
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  if (!isOpen) return null;

  const sarifData = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'Red Mercury',
            version: '1.2.0',
            informationUri: 'https://github.com/xerova/red-mercury',
            rules: Array.from(new Set(findings.map(f => f.cwe || 'CWE-Unknown'))).map(cwe => ({
              id: cwe,
              name: cwe,
              shortDescription: { text: `Vulnerability classification for ${cwe}` },
            })),
          },
        },
        results: findings.map(f => ({
          ruleId: f.cwe || 'CWE-Unknown',
          level:
            f.severity === 'CRITICAL' || f.severity === 'HIGH'
              ? 'error'
              : f.severity === 'MEDIUM'
              ? 'warning'
              : 'note',
          message: { text: f.title || 'Security vulnerability finding' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file_path || 'unknown' },
                region: { startLine: f.line_number || 1 },
              },
            },
          ],
        })),
      },
    ],
  };

  const jsonData = {
    exportedAt: new Date().toISOString(),
    engine: 'Red Mercury v1.2',
    totalFindings: findings.length,
    repositoriesCount: repositories.length,
    severityBreakdown: {
      critical: findings.filter(f => f.severity === 'CRITICAL').length,
      high: findings.filter(f => f.severity === 'HIGH').length,
      medium: findings.filter(f => f.severity === 'MEDIUM').length,
      low: findings.filter(f => f.severity === 'LOW').length,
    },
    repositories: repositories.map(r => ({ id: r.id, name: r.name, defaultBranch: r.default_branch })),
    findings: findings.map(f => ({
      id: f.id,
      title: f.title,
      cwe: f.cwe,
      severity: f.severity,
      filePath: f.file_path,
      lineNumber: f.line_number,
      scanner: f.scanner_name,
    })),
  };

  const summaryText = [
    `=======================================================`,
    `RED MERCURY — SECURITY AUDIT REPORT`,
    `Generated: ${new Date().toUTCString()}`,
    `=======================================================`,
    ``,
    `SUMMARY:`,
    `- Total Monitored Repositories: ${repositories.length}`,
    `- Total Open Findings: ${findings.length}`,
    `- Critical: ${findings.filter(f => f.severity === 'CRITICAL').length}`,
    `- High:     ${findings.filter(f => f.severity === 'HIGH').length}`,
    `- Medium:   ${findings.filter(f => f.severity === 'MEDIUM').length}`,
    `- Low:      ${findings.filter(f => f.severity === 'LOW').length}`,
    ``,
    `TOP VULNERABILITIES:`,
    ...findings.slice(0, 10).map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.file_path}:${f.line_number || 1})`),
    ``,
    `=======================================================`,
  ].join('\n');

  const handleDownload = async () => {
    let content = '';
    let mimeType = '';
    let filename = '';
    const exportFormat = format === 'summary' ? 'txt' : format;

    if (format === 'sarif') {
      content = JSON.stringify(sarifData, null, 2);
      mimeType = 'application/json';
      filename = 'red-mercury-findings.sarif';
    } else if (format === 'json') {
      content = JSON.stringify(jsonData, null, 2);
      mimeType = 'application/json';
      filename = 'red-mercury-audit-report.json';
    } else {
      content = summaryText;
      mimeType = 'text/plain';
      filename = 'red-mercury-security-summary.txt';
    }

    if (typeof window !== 'undefined' && window.electronAPI?.saveReport) {
      try {
        const res = await window.electronAPI.saveReport({
          defaultFilename: filename,
          content,
          format: exportFormat,
        });
        if (res?.saved) {
          setDownloadSuccess(true);
          setTimeout(() => setDownloadSuccess(false), 2500);
        }
        return;
      } catch {
        // Fall back to browser download if IPC save dialog fails
      }
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => {
      setDownloadSuccess(false);
    }, 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 font-sans backdrop-blur-2xs">
      <div className="relative w-full max-w-xl bg-white rounded-xl shadow-2xl border border-slate-200 flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-2xs">
              <Download className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">Export AppSec Compliance &amp; Audit Trail</h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Download findings in standard developer and compliance formats.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4">
          <div>
            <label className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider block mb-2 font-mono">
              Select Output Format
            </label>
            <div className="grid grid-cols-3 gap-2.5">
              <button
                type="button"
                onClick={() => setFormat('sarif')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  format === 'sarif'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold text-xs text-slate-900">SARIF v2.1</span>
                  <span className="text-[10px] font-mono font-semibold text-blue-600 uppercase">OASIS</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-tight">
                  Standard format for GitHub Advanced Security and CI/CD.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setFormat('json')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  format === 'json'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold text-xs text-slate-900">JSON</span>
                  <span className="text-[10px] font-mono font-semibold text-emerald-600 uppercase">Raw</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-tight">
                  Full programmatic findings dataset and repository metadata.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setFormat('summary')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  format === 'summary'
                    ? 'border-slate-900 bg-slate-50 shadow-2xs ring-1 ring-slate-900'
                    : 'border-slate-200 hover:bg-slate-50 text-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-bold text-xs text-slate-900">Text Summary</span>
                  <span className="text-[10px] font-mono font-semibold text-slate-500 uppercase">Audit</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-tight">
                  Human-readable executive audit and vulnerability list.
                </p>
              </button>
            </div>
          </div>

          {/* Payload Preview */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider font-mono">
                Preview ({format.toUpperCase()})
              </span>
              <span className="text-xs text-slate-400 font-mono">
                {findings.length} total findings
              </span>
            </div>
            <pre className="p-3.5 rounded-lg bg-slate-900 text-slate-200 font-mono text-[11px] overflow-x-auto max-h-40 border border-slate-800 shadow-inner">
              {format === 'sarif'
                ? JSON.stringify(sarifData, null, 2)
                : format === 'json'
                ? JSON.stringify(jsonData, null, 2)
                : summaryText}
            </pre>
          </div>

          {downloadSuccess && (
            <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 font-medium text-xs flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span>Report downloaded successfully.</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-200 bg-slate-50 flex items-center justify-end gap-2.5">
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-md border border-slate-200 bg-white hover:bg-slate-100 text-slate-700 text-xs font-medium transition-colors shadow-2xs cursor-pointer"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-md bg-slate-900 text-white hover:bg-slate-800 text-xs font-semibold transition-all shadow-2xs cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download {format.toUpperCase()}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
