import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api, BackendHealth } from '../services/api';

export const LandingPage: React.FC = () => {
  const { user } = useAuth();

  // Real backend connectivity & stats
  const [backendHealth, setBackendHealth] = useState<BackendHealth | null>(null);
  const [repoCount, setRepoCount] = useState<number>(0);
  const [findingCount, setFindingCount] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    api.getHealth()
      .then(health => {
        if (mounted) setBackendHealth(health);
      })
      .catch(() => {
        if (mounted) setBackendHealth(null);
      });

    Promise.all([
      api.getRepositories().catch(() => []),
      api.getFindings().catch(() => []),
    ]).then(([repos, findings]) => {
      if (mounted) {
        if (Array.isArray(repos) && repos.length > 0) setRepoCount(repos.length);
        if (Array.isArray(findings) && findings.length > 0) setFindingCount(findings.length);
      }
    });

    return () => {
      mounted = false;
    };
  }, []);

  return (
    <div className="min-h-screen bg-white text-slate-900 flex flex-col font-sans">
      {/* Top Header */}
      <header className="h-14 border-b border-slate-200 bg-white sticky top-0 z-50 px-4 lg:px-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-slate-900 flex items-center justify-center text-white shadow-xs">
              <span className="material-symbols-outlined text-lg">shield</span>
            </div>
            <div className="flex flex-col">
              <span className="font-semibold text-slate-900 text-sm tracking-tight leading-none">
                Red Mercury
              </span>
              <span className="text-[10px] text-slate-500 font-mono mt-0.5 font-medium">
                Fix Verification Engine
              </span>
            </div>
          </Link>
          <span className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-600 border border-slate-200 ml-1">
            v0.1.0
          </span>
        </div>

        {/* Real Functional In-Page Navigation */}
        <nav className="hidden md:flex items-center gap-7 text-xs font-medium text-slate-600">
          <a href="#how-it-works" className="hover:text-slate-900 transition-colors">How It Works</a>
          <a href="#architecture" className="hover:text-slate-900 transition-colors">Verification Architecture</a>
          <a href="#scanners" className="hover:text-slate-900 transition-colors">Scanners</a>
          <a href="#compliance" className="hover:text-slate-900 transition-colors">Compliance &amp; SARIF</a>
        </nav>

        <div className="flex items-center gap-2.5">
          {/* Live API Health indicator */}
          <div className="hidden lg:flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-[10px] font-mono bg-slate-50 border-slate-200 text-slate-600">
            <span className={`w-1.5 h-1.5 rounded-full ${backendHealth?.status === 'ok' ? 'bg-emerald-600' : 'bg-slate-400'}`} />
            <span>{backendHealth?.status === 'ok' ? 'API Online' : 'Local Mode'}</span>
          </div>

          <Link
            to="/login"
            className="px-3 py-1.5 text-xs font-medium text-slate-700 hover:text-slate-900 hover:bg-slate-100 rounded-md transition-colors"
          >
            Sign In
          </Link>
          <Link
            to={user?.isAuthenticated ? "/dashboard" : "/login"}
            className="px-3.5 py-1.5 text-xs font-medium text-white bg-slate-900 hover:bg-slate-800 rounded-md transition-all shadow-xs hover:shadow-sm flex items-center gap-1.5 active:scale-[0.98]"
          >
            <span>Launch Console</span>
            <span className="material-symbols-outlined text-sm">arrow_forward</span>
          </Link>
        </div>
      </header>

      {/* Hero Section */}
      <section className="pt-14 pb-12 px-4 lg:px-8 max-w-5xl mx-auto text-center flex flex-col items-center">
        {/* Release Pill */}
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-50 border border-slate-200 text-slate-700 text-xs font-medium mb-5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
          <span>Automated Security Fix Verification &amp; Pull Request Gates</span>
        </div>

        {/* Realistic Technical Headline */}
        <h1 className="text-3xl sm:text-5xl font-bold text-slate-900 tracking-tight leading-[1.15] max-w-3xl">
          Detect source vulnerabilities. <br />
          <span className="text-slate-500 font-semibold">Verify security fixes with proof.</span>
        </h1>

        {/* Clear Supporting Copy */}
        <p className="mt-4 text-sm sm:text-base text-slate-600 max-w-2xl leading-relaxed">
          Red Mercury correlates multi-scanner static analysis with AST reachability traces and runs regression test suites in isolated sandboxes to ensure fixes resolve vulnerabilities without breaking production code.
        </p>

        {/* Primary CTA Buttons */}
        <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
          <Link
            to={user?.isAuthenticated ? "/dashboard" : "/login"}
            className="px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs sm:text-sm rounded-lg transition-all shadow-xs hover:shadow-sm flex items-center gap-2 active:scale-[0.98]"
          >
            <span className="material-symbols-outlined text-base text-emerald-400">play_circle</span>
            <span>Launch Security Console</span>
          </Link>

          <a
            href="#how-it-works"
            className="px-5 py-2.5 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs sm:text-sm rounded-lg border border-slate-200 shadow-2xs transition-all hover:border-slate-300 flex items-center gap-1.5"
          >
            <span>Explore Verification Workflow</span>
            <span className="material-symbols-outlined text-sm text-slate-400">arrow_downward</span>
          </a>
        </div>

        {/* Live System Metrics Strip */}
        <div className="mt-8 w-full max-w-3xl grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3 rounded-xl bg-white border border-slate-200 shadow-2xs text-left">
          <div className="p-2 border-r border-slate-100 last:border-0">
            <span className="text-lg font-bold text-slate-900 font-mono block">{repoCount}</span>
            <span className="text-[11px] text-slate-500 font-medium">Monitored Repos</span>
          </div>
          <div className="p-2 border-r border-slate-100 last:border-0">
            <span className="text-lg font-bold text-slate-900 font-mono block">{findingCount} Active</span>
            <span className="text-[11px] text-slate-500 font-medium">Triaged Findings</span>
          </div>
          <div className="p-2 border-r border-slate-100 last:border-0">
            <span className="text-lg font-bold text-emerald-600 font-mono block">Differential</span>
            <span className="text-[11px] text-slate-500 font-medium">Regression Gate</span>
          </div>
          <div className="p-2">
            <span className="text-lg font-bold text-slate-900 font-mono block">&lt; 1.5s</span>
            <span className="text-[11px] text-slate-500 font-medium">Sandbox Runner</span>
          </div>
        </div>
      </section>

      {/* Section 1: How It Works */}
      <section id="how-it-works" className="py-16 bg-white border-t border-slate-200 px-4 lg:px-8 scroll-mt-14">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold block mb-1">
              End-to-End Workflow
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Automated Fix Verification Workflow
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-2">
              Red Mercury automates post-patch verification by testing candidate remediations against differential scans, syntax rules, and regression test suites before merging.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-5 rounded-xl border border-slate-200 bg-slate-50 flex flex-col justify-between">
              <div>
                <div className="w-8 h-8 rounded-lg bg-slate-900 text-white font-mono text-xs font-bold flex items-center justify-center mb-3">
                  01
                </div>
                <h3 className="text-sm font-bold text-slate-900">Multi-Scanner Ingestion</h3>
                <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                  Aggregates and normalizes alerts across Bandit (SAST), Semgrep (Polyglot), pip-audit (SCA), and Gitleaks into a unified CWE schema.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-200 text-xs text-slate-500">
                Subprocess isolation • 60s timeout
              </div>
            </div>

            <div className="p-5 rounded-xl border border-slate-200 bg-slate-50 flex flex-col justify-between">
              <div>
                <div className="w-8 h-8 rounded-lg bg-slate-900 text-white font-mono text-xs font-bold flex items-center justify-center mb-3">
                  02
                </div>
                <h3 className="text-sm font-bold text-slate-900">AST Taint &amp; Risk Scoring</h3>
                <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                  Calculates contextual priority scores using CVSS v3.1, EPSS exploit probabilities, and compiler AST reachability traces.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-200 text-xs text-slate-500">
                Reachability &amp; dataflow filtering
              </div>
            </div>

            <div className="p-5 rounded-xl border border-slate-200 bg-slate-50 flex flex-col justify-between">
              <div>
                <div className="w-8 h-8 rounded-lg bg-slate-900 text-white font-mono text-xs font-bold flex items-center justify-center mb-3">
                  03
                </div>
                <h3 className="text-sm font-bold text-slate-900">Sandboxed Verification</h3>
                <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                  Applies candidate diff patches in isolated runners. Re-executes static differential scans and complete unit and regression suites.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-200 text-xs text-slate-500">
                Pre- vs. post-patch validation
              </div>
            </div>

            <div className="p-5 rounded-xl border border-slate-200 bg-slate-50 flex flex-col justify-between">
              <div>
                <div className="w-8 h-8 rounded-lg bg-emerald-600 text-white font-mono text-xs font-bold flex items-center justify-center mb-3">
                  04
                </div>
                <h3 className="text-sm font-bold text-slate-900">Automated PR Merge Gate</h3>
                <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                  Only patches that pass all three gates (differential scan, syntax check, unit tests) receive cryptographic sign-off for PR merge.
                </p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-200 text-xs text-emerald-700 font-medium">
                SHA-256 verifiable audit record
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 2: Verification Architecture */}
      <section id="architecture" className="py-16 bg-slate-50 border-t border-slate-200 px-4 lg:px-8 scroll-mt-14">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-xs uppercase tracking-wider text-slate-500 font-semibold block mb-1">
              System Architecture
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Fix Verification Architecture
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-2">
              How Red Mercury verifies remediations against static analysis rules and test suites before deployment.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-xl p-6 sm:p-8 shadow-2xs">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex flex-col">
                <div className="flex items-center gap-2 mb-2 text-xs font-bold text-slate-900">
                  <span className="w-2 h-2 rounded-full bg-blue-600" />
                  <span>1. BASELINE CONTEXT EXTRACTION</span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  Extracts targeted code scopes with bounded context (+/- 15 lines). Automatically scrubs credentials and tokens (API keys, JWTs) before analysis.
                </p>
                <div className="mt-auto pt-3 text-xs text-slate-500">
                  Pre-ingestion secret redaction
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex flex-col">
                <div className="flex items-center gap-2 mb-2 text-xs font-bold text-slate-900">
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                  <span>2. SECURE REMEDIATION ENGINE</span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  Synthesizes remediation proposals with strict input segregation. Untrusted code comments and commit messages cannot override verification policies.
                </p>
                <div className="mt-auto pt-3 text-xs text-slate-500">
                  Deterministic policy guardrails
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 flex flex-col">
                <div className="flex items-center gap-2 mb-2 text-xs font-bold text-slate-900">
                  <span className="w-2 h-2 rounded-full bg-emerald-600" />
                  <span>3. REPLAY &amp; MERGE GATE</span>
                </div>
                <p className="text-xs text-slate-600 leading-relaxed">
                  Executes regression tests, validates AST syntax, and confirms scanner findings resolve to zero without introducing secondary regressions.
                </p>
                <div className="mt-auto pt-3 text-xs text-emerald-700 font-medium">
                  Automated merge gate verification
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 3: Scanners & Integrations */}
      <section id="scanners" className="py-16 bg-white border-t border-slate-200 px-4 lg:px-8 scroll-mt-14">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold block mb-1">
              Multi-Scanner Fleet
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Supported Security Engines &amp; Scanners
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-2">
              Red Mercury orchestrates industry-standard open-source security tools via modular adapters.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-purple-600">security</span>
                <span>Semgrep &amp; Bandit</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Polyglot AST pattern matching detecting structural code flaws, SQL injection, and command injection.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-purple-50 border border-purple-200 text-purple-700">
                SAST • Polyglot
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-rose-600">code_blocks</span>
                <span>SQL &amp; NoSQL Injections</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Identifies unparameterized raw SQL concatenation and MongoDB/Mongoose operator injections.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-700">
                CWE-89 • CWE-943
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-emerald-600">inventory_2</span>
                <span>Trivy &amp; Pip-Audit (SCA)</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Cross-ecosystem dependency analysis scanning npm, pip, go, maven, and cargo against live CVE advisories.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700">
                SCA • Dependencies
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-rose-600">key</span>
                <span>Gitleaks Secret Guard</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Shannon entropy and regular expression scanning detecting API keys, private tokens, and passwords.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-rose-700">
                Secrets • Auto-Redaction
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-amber-600">deployed_code</span>
                <span>IaC &amp; Vulnerability Scanner</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Audits Dockerfiles, Kubernetes manifests, and Compose files for root users and privileged containers.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-700">
                IaC • Containers
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-blue-600">language</span>
                <span>DAST &amp; OWASP ZAP</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Dynamic probes verifying HTTP headers (HSTS, CSP), cookie security flags, and permissive CORS.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-700">
                DAST • Web Runtime
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-indigo-600">api</span>
                <span>API Security (OWASP API Top 10)</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Validates OpenAPI/Swagger contracts and route handlers for BOLA/IDOR, broken auth, and missing limits.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-700">
                API Security
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-teal-600">motion_sensor_active</span>
                <span>IAST Sensor &amp; Execution Sinks</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Interactive flow analysis tracing dangerous deserialization sinks, eval/exec vectors, and SSTI hooks.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-teal-50 border border-teal-200 text-teal-700">
                IAST • Execution Sinks
              </span>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50">
              <div className="flex items-center gap-2 mb-2 font-semibold text-slate-900 text-sm">
                <span className="material-symbols-outlined text-base text-orange-600">verified_user</span>
                <span>OWASP Suite &amp; Pentest Recon</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed mb-3">
                Reconnaissance engine detecting exposed environment files, sensitive endpoints, and weak cryptography.
              </p>
              <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-orange-50 border border-orange-200 text-orange-700">
                OWASP Top 10 • Pentest
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Section 4: Compliance & Evidence */}
      <section id="compliance" className="py-16 bg-slate-50 border-t border-slate-200 px-4 lg:px-8 scroll-mt-14">
        <div className="max-w-5xl mx-auto">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold block mb-1">
              Audit &amp; Assurance
            </span>
            <h2 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Cryptographic Evidence &amp; SARIF Compliance
            </h2>
            <p className="text-xs sm:text-sm text-slate-600 mt-2">
              Every verification decision produces a tamper-evident audit trail ready for enterprise compliance.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs">
              <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-3">
                <span className="material-symbols-outlined text-lg">file_download</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">SARIF 2.1.0 Standard</h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Exports standardized Static Analysis Results Interchange Format (SARIF) documents compatible with GitHub Advanced Security and DefectDojo.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs">
              <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-3">
                <span className="material-symbols-outlined text-lg">lock</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">SHA-256 Evidence Hashing</h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Hashes pre-patch baseline, proposed diff, test output logs, and verification decisions to guarantee audit integrity and non-repudiation.
              </p>
            </div>

            <div className="p-6 rounded-xl border border-slate-200 bg-white shadow-2xs">
              <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-3">
                <span className="material-symbols-outlined text-lg">integration_instructions</span>
              </div>
              <h3 className="text-sm font-bold text-slate-900">CI/CD PR Gate Runner</h3>
              <p className="mt-2 text-xs text-slate-600 leading-relaxed">
                Includes standalone Python CLI runner (`scripts/ci_security_gate.py`) and GitHub Action workflow to automatically block PRs with regressions.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Bottom CTA Card */}
      <section className="py-16 bg-slate-50 border-t border-slate-200 px-4 lg:px-8">
        <div className="max-w-4xl mx-auto text-center flex flex-col items-center bg-white p-8 sm:p-12 rounded-xl border border-slate-200 shadow-2xs">
          <div className="w-10 h-10 rounded-lg bg-slate-100 text-slate-800 flex items-center justify-center mb-4">
            <span className="material-symbols-outlined text-2xl">verified</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
            Automated security fix verification for your repositories
          </h2>
          <p className="mt-3 text-xs sm:text-sm text-slate-600 max-w-xl leading-relaxed">
            Monitor repositories, triage security findings, and verify candidate fixes in isolated sandboxes before merging to production.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link
              to={user?.isAuthenticated ? "/dashboard" : "/login"}
              className="px-5 py-2.5 bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs sm:text-sm rounded-lg transition-all shadow-xs flex items-center gap-2"
            >
              <span className="material-symbols-outlined text-base text-emerald-400">play_circle</span>
              <span>Launch Security Console</span>
            </Link>
            <Link
              to="/login"
              className="px-5 py-2.5 bg-white hover:bg-slate-50 text-slate-700 font-medium text-xs sm:text-sm rounded-lg border border-slate-200 shadow-2xs transition-colors"
            >
              Sign In with SSO
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-8 px-4 lg:px-8 text-xs text-slate-500 font-mono">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-800">Red Mercury</span>
            <span>•</span>
            <span>Enterprise AppSec Division by Xerova</span>
          </div>
          <div className="flex items-center gap-4 text-slate-600">
            <Link to="/login" className="hover:text-slate-900">Sign In</Link>
            <Link to="/dashboard" className="hover:text-slate-900">Console</Link>
            <Link to="/repositories" className="hover:text-slate-900">Repositories</Link>
            <Link to="/findings" className="hover:text-slate-900">Findings</Link>
            <Link to="/verification" className="hover:text-slate-900">Fix Verification</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};
