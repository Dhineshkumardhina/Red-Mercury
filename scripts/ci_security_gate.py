#!/usr/bin/env python3
"""Standalone Machine-Readable CI Security Gate for Red Mercury.

Provides DevSecOps gate evaluation for Pull Requests and CI/CD pipelines:
1. Associates scans with exact repository and commit SHAs.
2. Analyzes changed code (diff-aware analysis).
3. Distinguishes NEW, RESOLVED, UNCHANGED, and REGRESSED findings.
4. Displays fix-verification evidence alongside candidate patches.
5. Emits standardized machine-readable JSON (and optional SARIF / Markdown).
6. Returns non-success exit codes:
   - 0: PASS (clean security gate, zero blocking findings, all checks completed).
   - 1: FAIL (security policy failure: new or regressed high/critical findings or test failures).
   - 2: INCOMPLETE (configured checks unavailable, skipped, or timed out).
7. Audits omissions (distinguishes failed checks from unavailable checks).
8. Outputs reproducible local CLI commands for developers.
9. Preserves links to complete finding and verification evidence records.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Add workspace and backend directories to path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

try:
    from app.integrations.github.pr_analyzer import PRAnalysisResult, PRAnalyzer, normalize_file_path
    from app.integrations.github.publisher import generate_pr_summary_markdown
    from app.integrations.github.schemas import CategorizedPRFinding, FindingClassification, PRVerificationSummary
except ImportError:
    # Standalone fallback if package structure differs in CI container
    PRAnalyzer = None


SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Sensitive patterns to redact from findings, evidence, summaries, and messages
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{82}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"glpat-[a-zA-Z0-9_\-]{20}"), "[REDACTED_GITLAB_TOKEN]"),
    (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"\b(sk_live_[0-9a-zA-Z]{24}|sk_test_[0-9a-zA-Z]{24}|FAKE_STRIPE_KEY[A-Za-z0-9_]*)\b"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"(password|passwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), r"\1 = '[REDACTED_SECRET]'"),
]


def redact_secrets_in_text(text: Optional[str]) -> str:
    """Mask secrets and credential tokens from strings."""
    if not text:
        return ""
    clean = str(text)
    for pattern, replacement in SECRET_PATTERNS:
        clean = pattern.sub(replacement, clean)
    return clean


def sanitize_dict_secrets(obj: Any) -> Any:
    """Recursively redact secrets across nested dicts, lists, and strings."""
    if isinstance(obj, str):
        return redact_secrets_in_text(obj)
    elif isinstance(obj, dict):
        return {k: sanitize_dict_secrets(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_dict_secrets(item) for item in obj]
    return obj


def _get_git_commit(cwd: Path, rev: str = "HEAD") -> str:
    """Retrieve full 40-character commit hash from local git workspace."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", rev],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return rev


def _get_git_changed_files(cwd: Path, base_sha: str, head_sha: str) -> List[str]:
    """Retrieve list of changed files between base and head revisions."""
    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", f"{base_sha}...{head_sha}"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        files = [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
        if files:
            return files
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def run_ci_security_gate(
    repo_path: Path,
    head_sha: Optional[str] = None,
    base_sha: Optional[str] = None,
    changed_files: Optional[List[str]] = None,
    fail_on_severity: str = "HIGH",
    strict_checks: bool = True,
    baseline_findings_file: Optional[Path] = None,
    head_findings_file: Optional[Path] = None,
    verifications_file: Optional[Path] = None,
    output_format: str = "json",
    output_file: Optional[Path] = None,
    pr_number: Optional[int] = None,
    failed_checks: Optional[List[str]] = None,
    unavailable_checks: Optional[List[str]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Execute CI security evaluation and return exit_code and structured payload."""
    repo_path = repo_path.resolve()
    resolved_head_sha = head_sha or _get_git_commit(repo_path, "HEAD")
    resolved_base_sha = base_sha or _get_git_commit(repo_path, "HEAD~1")

    if not changed_files:
        changed_files = _get_git_changed_files(repo_path, resolved_base_sha, resolved_head_sha)

    norm_changed_files = [f.replace("\\", "/").strip().lstrip("/") for f in (changed_files or [])]
    changed_files_set = set(norm_changed_files)

    unavailable_checks_list: List[str] = list(unavailable_checks or [])
    failed_checks_list: List[str] = list(failed_checks or [])

    # 1. Load baseline & head findings
    baseline_findings: List[Dict[str, Any]] = []
    if baseline_findings_file:
        if not baseline_findings_file.exists():
            failed_checks_list.append(f"Baseline findings file not found on disk: {baseline_findings_file}")
        else:
            try:
                with open(baseline_findings_file, "r", encoding="utf-8") as f:
                    baseline_findings = json.load(f)
            except Exception as e:
                failed_checks_list.append(f"Failed to parse baseline findings JSON: {e}")

    head_findings: List[Dict[str, Any]] = []
    if head_findings_file:
        if not head_findings_file.exists():
            failed_checks_list.append(f"Head findings file not found on disk: {head_findings_file}")
        else:
            try:
                with open(head_findings_file, "r", encoding="utf-8") as f:
                    head_findings = json.load(f)
            except Exception as e:
                failed_checks_list.append(f"Failed to parse head findings JSON: {e}")

    # 2. Check tool availability and omission auditing
    scanners_executed: List[str] = []

    # Check for installed security scanners
    scanner_binaries = {
        "Semgrep OSS": "semgrep",
        "Bandit": "bandit",
        "pip-audit": "pip-audit",
    }
    for display_name, bin_name in scanner_binaries.items():
        found = False
        try:
            res = subprocess.run([bin_name, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                found = True
        except Exception:
            found = False

        if found:
            scanners_executed.append(display_name)
        else:
            unavailable_checks_list.append(f"{display_name}: Scanner binary '{bin_name}' not detected in environment PATH")

    # If head_findings_file was not provided, execute live scans with available scanners
    if head_findings_file is None:
        if "Bandit" in scanners_executed:
            try:
                bandit_res = subprocess.run(
                    ["bandit", "-r", str(repo_path), "-f", "json", "--exclude", "tests,venv,.venv,backend/data/workspaces,samples"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if bandit_res.returncode in (0, 1):
                    try:
                        b_data = json.loads(bandit_res.stdout)
                        for item in b_data.get("results", []):
                            head_findings.append({
                                "rule_id": item.get("test_id", "BANDIT"),
                                "title": item.get("issue_text", "Bandit Finding"),
                                "message": item.get("issue_text", ""),
                                "severity": item.get("issue_severity", "MEDIUM"),
                                "confidence": item.get("issue_confidence", "MEDIUM"),
                                "file_path": item.get("filename", "").replace("\\", "/"),
                                "line_number": item.get("line_number"),
                                "scanner_name": "bandit",
                            })
                    except Exception as e:
                        failed_checks_list.append(f"Bandit: Failed to parse JSON output: {e}")
                else:
                    err_msg = bandit_res.stderr.strip() or f"exited with code {bandit_res.returncode}"
                    failed_checks_list.append(f"Bandit: Scanner execution error ({err_msg})")
            except Exception as exc:
                failed_checks_list.append(f"Bandit: Scanner execution exception: {exc}")

        if "Semgrep OSS" in scanners_executed:
            try:
                semgrep_res = subprocess.run(
                    ["semgrep", "scan", "--config=auto", "--json", "--exclude", "tests", "--exclude", "backend/data/workspaces", "--quiet", str(repo_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if semgrep_res.returncode in (0, 1):
                    try:
                        s_data = json.loads(semgrep_res.stdout)
                        for item in s_data.get("results", []):
                            extra = item.get("extra", {})
                            sev = extra.get("severity", "WARNING").upper()
                            sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                            head_findings.append({
                                "rule_id": item.get("check_id", "SEMGREP"),
                                "title": extra.get("message", "Semgrep Finding"),
                                "message": extra.get("message", ""),
                                "severity": sev_map.get(sev, "MEDIUM"),
                                "confidence": "HIGH",
                                "file_path": item.get("path", "").replace("\\", "/"),
                                "line_number": item.get("start", {}).get("line"),
                                "scanner_name": "semgrep",
                            })
                    except Exception as e:
                        failed_checks_list.append(f"Semgrep OSS: Failed to parse JSON output: {e}")
                else:
                    err_msg = semgrep_res.stderr.strip() or f"exited with code {semgrep_res.returncode}"
                    failed_checks_list.append(f"Semgrep OSS: Scanner execution error ({err_msg})")
            except Exception as exc:
                failed_checks_list.append(f"Semgrep OSS: Scanner execution exception: {exc}")

        if "pip-audit" in scanners_executed and (repo_path / "requirements.txt").exists():
            try:
                pip_res = subprocess.run(
                    ["pip-audit", "-r", str(repo_path / "requirements.txt"), "-f", "json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if pip_res.returncode in (0, 1):
                    try:
                        p_data = json.loads(pip_res.stdout)
                        for dep in p_data.get("dependencies", []):
                            for vuln in dep.get("vulns", []):
                                head_findings.append({
                                    "rule_id": vuln.get("id", "PIP-AUDIT"),
                                    "title": f"Vulnerability in {dep.get('name')}",
                                    "message": vuln.get("description", ""),
                                    "severity": "HIGH",
                                    "confidence": "HIGH",
                                    "file_path": "requirements.txt",
                                    "scanner_name": "pip-audit",
                                })
                    except Exception as e:
                        failed_checks_list.append(f"pip-audit: Failed to parse JSON output: {e}")
                else:
                    err_msg = pip_res.stderr.strip() or f"exited with code {pip_res.returncode}"
                    failed_checks_list.append(f"pip-audit: Scanner execution error ({err_msg})")
            except Exception as exc:
                failed_checks_list.append(f"pip-audit: Scanner execution exception: {exc}")

    # 3. Categorize findings into NEW, RESOLVED, UNCHANGED, and REGRESSED
    categorized_findings: List[Dict[str, Any]] = []
    base_fp_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for bf in baseline_findings:
        fp = ((bf.get("rule_id") or "GENERAL").lower().strip(), (bf.get("file_path") or "").replace("\\", "/").lower().lstrip("/"))
        base_fp_map[fp] = bf

    seen_head_fps = set()
    new_count = 0
    resolved_count = 0
    unchanged_count = 0
    regressed_count = 0

    threshold_level = SEVERITY_LEVELS.get(fail_on_severity.upper(), 3)
    policy_violations: List[str] = []

    for hf in head_findings:
        rule_id = hf.get("rule_id", "GENERAL")
        file_path = hf.get("file_path", "").replace("\\", "/").lstrip("/")
        fp = (rule_id.lower().strip(), file_path.lower())
        seen_head_fps.add(fp)

        is_changed_file = file_path in changed_files_set or any(file_path.endswith(cf) for cf in changed_files_set) if changed_files_set else True
        severity = (hf.get("severity") or "MEDIUM").upper()
        sev_level = SEVERITY_LEVELS.get(severity, 2)

        if fp in base_fp_map:
            unchanged_count += 1
            cat_item = dict(hf)
            cat_item.update({"classification": "UNCHANGED", "commit_sha": resolved_head_sha})
            categorized_findings.append(cat_item)
        else:
            if is_changed_file:
                new_count += 1
                cat_item = dict(hf)
                cat_item.update({"classification": "NEW", "commit_sha": resolved_head_sha})
                categorized_findings.append(cat_item)
                if sev_level >= threshold_level:
                    policy_violations.append(f"NEW finding exceeds threshold: {severity} '{rule_id}' in {file_path}")
            else:
                if baseline_findings_file:
                    regressed_count += 1
                    cat_item = dict(hf)
                    cat_item.update({"classification": "REGRESSED", "commit_sha": resolved_head_sha})
                    categorized_findings.append(cat_item)
                    if sev_level >= threshold_level:
                        policy_violations.append(f"REGRESSED finding detected in unchanged file '{file_path}': {severity} '{rule_id}'")
                else:
                    unchanged_count += 1
                    cat_item = dict(hf)
                    cat_item.update({"classification": "UNCHANGED", "commit_sha": resolved_head_sha})
                    categorized_findings.append(cat_item)

    for fp, bf in base_fp_map.items():
        if fp not in seen_head_fps:
            bf_file = (bf.get("file_path") or "").replace("\\", "/").lstrip("/")
            if bf_file in changed_files_set or any(bf_file.endswith(cf) for cf in changed_files_set) or not changed_files_set:
                resolved_count += 1
                cat_item = dict(bf)
                cat_item.update({
                    "classification": "RESOLVED",
                    "commit_sha": resolved_head_sha,
                    "message": f"Resolved: {bf.get('message', '')}",
                })
                categorized_findings.append(cat_item)

    # 4. Load Fix Verification evidence if provided
    verification_summaries: List[Dict[str, Any]] = []
    if verifications_file:
        if not verifications_file.exists():
            failed_checks_list.append(f"Verification evidence file not found on disk: {verifications_file}")
        else:
            try:
                with open(verifications_file, "r", encoding="utf-8") as f:
                    v_data = json.load(f)
                    verification_summaries = v_data if isinstance(v_data, list) else [v_data]
            except Exception as e:
                failed_checks_list.append(f"Failed to parse verifications JSON: {e}")

    # 5. Evaluate CI Gate Policy
    # Failed checks include policy violations and execution errors
    all_failed_checks = list(dict.fromkeys(failed_checks_list + policy_violations))

    if all_failed_checks:
        gate_status = "FAIL"
        exit_code = 1
        gate_passed = False
    elif unavailable_checks_list and strict_checks:
        gate_status = "INCOMPLETE"
        exit_code = 2
        gate_passed = False
    else:
        gate_status = "PASS"
        exit_code = 0
        gate_passed = True

    # 6. Build Local Reproduction Command
    repro_cmd = f"python -m scripts.ci_security_gate --repo-path . --head-sha {resolved_head_sha[:8]} --base-sha {resolved_base_sha[:8]} --fail-on {fail_on_severity.upper()}"

    # 7. Generate Actionable Pull Request Markdown Summary
    md_lines: List[str] = [
        f"## 🛡️ Red Mercury — CI Security Gate Evaluation",
        f"**Repository:** `{repo_path.name}` | **Commit:** `{resolved_head_sha[:8]}` (`{resolved_head_sha}`) | **Base:** `{resolved_base_sha[:8]}` | **Gate Status:** `{gate_status}`",
        "",
        f"| 🚨 New Findings | ✅ Resolved | ⚠️ Regressed | ℹ️ Unchanged | 🔬 Verified Fixes | Scanners Checked |",
        f"| :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **{new_count}** | **{resolved_count}** | **{regressed_count}** | {unchanged_count} | **{len(verification_summaries)}** | {len(scanners_executed)} |",
        "",
    ]

    if gate_status == "FAIL":
        md_lines.append(
            "> [!CAUTION]\n"
            f"> **Security Gate FAILED:** This pull request introduces **{new_count} new** and **{regressed_count} regressed** "
            f"security findings violating the `{fail_on_severity}` policy threshold. CI build blocked."
        )
    elif gate_status == "INCOMPLETE":
        md_lines.append(
            "> [!WARNING]\n"
            f"> **Security Gate INCOMPLETE:** {len(unavailable_checks_list)} configured security checks were unavailable or omitted. "
            "Under strict DevSecOps policy, unverified builds cannot pass silently."
        )
    elif resolved_count > 0 and new_count == 0:
        md_lines.append(
            "> [!TIP]\n"
            f"> **Security Gate PASSED:** Pull request successfully verified **{resolved_count}** remediated vulnerability(ies) "
            "with zero new issues detected on configured checks."
        )
    else:
        md_lines.append(
            "> [!NOTE]\n"
            "> **Security Gate PASSED:** Configured static analysis checks detected zero policy-violating findings."
        )
    md_lines.append("")

    # Fix Verification Evidence Section
    if verification_summaries:
        md_lines.append("### 🔬 Proposed Fixes & Verification Evidence")
        md_lines.append("| Finding / Fix | Status | Verification Evidence | Report |")
        md_lines.append("| :--- | :--- | :--- | :--- |")
        for v in verification_summaries:
            status_val = v.get("status", "VERIFIED")
            status_icon = "✅" if "VERIFIED" in status_val else "❌" if "FAILED" in status_val else "⚠️"
            title = v.get("finding_title") or v.get("rule_id") or "Security Fix"
            file_loc = f"`{v.get('file_path')}`" if v.get("file_path") else "`Workspace`"
            items = v.get("evidence_items") or [f"Status: {status_val}"]
            ev_str = "<br>".join([f"• {i}" for i in items])
            rep_link = f"[Report]({v.get('evidence_report_link')})" if v.get("evidence_report_link") else "-"
            md_lines.append(f"| **{title}**<br>{file_loc} | {status_icon} `{status_val}` | {ev_str} | {rep_link} |")
        md_lines.append("")

    # Detailed findings table
    if categorized_findings:
        md_lines.append("### 📋 Security Findings Detail")
        md_lines.append("| Status | Severity | Finding / Rule | File & Line | Link |")
        md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for cf in categorized_findings:
            icon = "🚨" if cf.get("classification") == "NEW" else \
                   "✅" if cf.get("classification") == "RESOLVED" else \
                   "⚠️" if cf.get("classification") == "REGRESSED" else "ℹ️"
            line_str = f"L{cf.get('line_number')}" if cf.get("line_number") else "-"
            dt_link = f"[Details]({cf.get('detail_url')})" if cf.get("detail_url") else "-"
            md_lines.append(f"| {icon} {cf.get('classification')} | **{cf.get('severity')}** | `{cf.get('rule_id')}`: {str(cf.get('message', ''))[:60]} | `{cf.get('file_path')}:{line_str}` | {dt_link} |")
        md_lines.append("")

    # Failed checks
    if all_failed_checks:
        md_lines.append("### ❌ Failed Security Checks")
        for fc in all_failed_checks:
            md_lines.append(f"- ❌ **{fc}**")
        md_lines.append("")

    # Unavailable / skipped checks (Omission auditing)
    if unavailable_checks_list:
        md_lines.append("### ⚠️ Checks Not Performed / Incomplete (Omission Auditing)")
        for uc in unavailable_checks_list:
            md_lines.append(f"- ⚠️ **{uc}**")
        md_lines.append("")

    # Local reproduction
    md_lines.append("### 💻 Local Reproduction")
    md_lines.append("Developers can reproduce this evaluation locally:")
    md_lines.append("```bash")
    md_lines.append(repro_cmd)
    md_lines.append("```")
    md_lines.append("")

    # Links
    md_lines.append("### 🔗 Full Reports & Evidence")
    md_lines.append("- 📋 [Full Findings Catalog](file:///docs/SCANNERS.md)")
    md_lines.append("- 🔬 [Fix Verification Engine Framework](file:///docs/VERIFICATION.md)")
    md_lines.append("- 📖 [DevSecOps Integration Architecture](file:///docs/CI_CD_CODE_REVIEW_INTEGRATION.md)")
    md_lines.append("")
    md_lines.append(
        "---  \n"
        "*Disclaimer: Red Mercury analysis reflects static scanner results and targeted verification checks on supported file formats. "
        "Passing checks do not provide cryptographic mathematical proof of universal security or exploit impossibility. "
        "Automated merging or deploying of proposed fixes is strictly prohibited without explicit operator review.*"
    )

    summary_markdown = "\n".join(md_lines)

    # 8. Assemble Machine-Readable JSON Output
    result_payload: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "repository": repo_path.name,
        "repository_path": str(repo_path),
        "head_commit_sha": resolved_head_sha,
        "base_commit_sha": resolved_base_sha,
        "gate_status": gate_status,
        "exit_code": exit_code,
        "gate_passed": gate_passed,
        "policy": {
            "fail_on_severity": fail_on_severity.upper(),
            "strict_checks": strict_checks,
        },
        "metrics": {
            "new_findings": new_count,
            "resolved_findings": resolved_count,
            "regressed_findings": regressed_count,
            "unchanged_findings": unchanged_count,
            "verified_fixes": len(verification_summaries),
            "failed_checks": len(all_failed_checks),
            "unavailable_checks": len(unavailable_checks_list),
        },
        "changed_files": norm_changed_files,
        "failed_checks": all_failed_checks,
        "unavailable_checks": unavailable_checks_list,
        "categorized_findings": categorized_findings,
        "verification_evidence": verification_summaries,
        "summary_markdown": summary_markdown,
        "reproduction": {
            "command": repro_cmd,
            "guide": "docs/CI_CD_CODE_REVIEW_INTEGRATION.md",
        },
        "report_links": {
            "findings_dashboard": f"/repositories/{repo_path.name}/findings",
            "verification_docs": "docs/VERIFICATION.md",
            "ci_cd_guide": "docs/CI_CD_CODE_REVIEW_INTEGRATION.md",
        },
        "sarif": _generate_sarif_report(repo_path, resolved_head_sha, categorized_findings),
    }

    # Sanitize all sensitive tokens/secrets before emission
    result_payload = sanitize_dict_secrets(result_payload)
    summary_markdown = result_payload["summary_markdown"]

    # Write output to file if requested
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            if output_format.lower() == "markdown":
                f.write(summary_markdown)
            elif output_format.lower() == "sarif":
                json.dump(result_payload["sarif"], f, indent=2)
            else:
                json.dump(result_payload, f, indent=2)

    return exit_code, result_payload


def _generate_sarif_report(
    repo_path: Path,
    head_sha: str,
    categorized_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Generate standard OASIS SARIF v2.1.0 report for GitHub Code Scanning."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for f in categorized_findings:
        rule_id = str(f.get("rule_id") or "SECURITY-RULE")
        cwe = str(f.get("cwe") or "")
        severity = str(f.get("severity") or "MEDIUM").upper()

        if severity in ("CRITICAL", "HIGH"):
            level = "error"
        elif severity == "MEDIUM":
            level = "warning"
        elif severity == "LOW":
            level = "note"
        else:
            level = "none"

        if rule_id not in rules_map:
            rule_desc = f.get("title") or f.get("message") or f"Security finding {rule_id}"
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", "_"),
                "shortDescription": {"text": str(rule_desc)[:200]},
                "fullDescription": {"text": str(f.get("message") or rule_desc)},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security", "redmercury"] + ([cwe] if cwe else []),
                    "precision": "high",
                },
            }

        file_path = str(f.get("file_path") or "unknown").replace("\\", "/").lstrip("/")
        line_num = int(f.get("line_number") or 1)
        if line_num <= 0:
            line_num = 1

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(f.get("message") or f.get("title") or rule_id)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                        },
                    }
                }
            ],
            "properties": {
                "classification": f.get("classification", "NEW"),
                "severity": severity,
                "scanner": f.get("scanner_name") or f.get("scanner_identifier") or "Red Mercury",
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Red Mercury",
                        "organization": "Red Mercury DevSecOps",
                        "version": "0.1.0",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/xerova/red-mercury",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
                "results": sarif_results,
            }
        ],
    }


def parse_severity_threshold(val: str) -> str:
    """Normalize severity threshold choices, supporting aliases like high_or_critical."""
    if not val:
        return "HIGH"
    norm = str(val).strip().upper()
    if norm in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return norm
    if norm in ("HIGH_OR_CRITICAL", "CRITICAL_OR_HIGH"):
        return "HIGH"
    if norm in ("MEDIUM_OR_HIGH", "HIGH_OR_MEDIUM"):
        return "MEDIUM"
    if norm in ("LOW_OR_HIGHER", "ANY", "ALL"):
        return "LOW"
    raise argparse.ArgumentTypeError(
        f"Invalid severity threshold '{val}'. Supported choices: CRITICAL, HIGH, MEDIUM, LOW (or high_or_critical)."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Red Mercury — Standalone CI Security Gate for Code Review & Pipelines"
    )
    # Support both canonical --repo-path and documented alias --workspace
    parser.add_argument(
        "--repo-path",
        "--workspace",
        dest="repo_path",
        type=str,
        default=".",
        help="Path to local repository workspace (aliases: --repo-path, --workspace)",
    )
    parser.add_argument("--head-sha", type=str, default=None, help="Head commit SHA to evaluate")
    parser.add_argument("--base-sha", type=str, default=None, help="Base commit SHA target")
    parser.add_argument("--changed-files", type=str, default=None, help="Comma-separated list of changed files")
    # Support canonical choices and documented aliases
    parser.add_argument(
        "--fail-on",
        type=parse_severity_threshold,
        default="HIGH",
        help="Severity threshold to fail the gate (e.g. CRITICAL, HIGH, MEDIUM, LOW, high_or_critical)",
    )
    parser.add_argument("--strict-checks", action="store_true", default=True, help="Fail gate if required checks are unavailable or skipped")
    parser.add_argument("--no-strict-checks", dest="strict_checks", action="store_false", help="Permit scans with unavailable checks to pass")
    parser.add_argument("--baseline-findings", type=str, default=None, help="Path to baseline findings JSON")
    parser.add_argument("--head-findings", type=str, default=None, help="Path to head findings JSON")
    parser.add_argument("--verifications-file", type=str, default=None, help="Path to fix verification records JSON")
    # Support sarif format alongside json, markdown, and text
    parser.add_argument(
        "--format",
        type=str.lower,
        default="json",
        choices=["json", "markdown", "text", "sarif"],
        help="Console output format: json, markdown, text, or sarif",
    )
    # Support both canonical --output-file and documented alias --output-report
    parser.add_argument(
        "--output-file",
        "--output-report",
        dest="output_file",
        type=str,
        default=None,
        help="File path to write machine-readable evaluation report (aliases: --output-file, --output-report)",
    )
    parser.add_argument("--pr-number", type=int, default=None, help="Pull request number")
    parser.add_argument(
        "--failed-check",
        dest="failed_checks",
        action="append",
        default=[],
        help="Explicitly record a failed security check or scanner execution error",
    )
    parser.add_argument(
        "--scanner-failure",
        dest="failed_checks",
        action="append",
        help="Alias to record a scanner execution failure",
    )

    try:
        args = parser.parse_args()

        changed_list = [f.strip() for f in args.changed_files.split(",")] if args.changed_files else None
        base_file = Path(args.baseline_findings) if args.baseline_findings else None
        head_file = Path(args.head_findings) if args.head_findings else None
        verif_file = Path(args.verifications_file) if args.verifications_file else None
        out_file = Path(args.output_file) if args.output_file else None

        exit_code, payload = run_ci_security_gate(
            repo_path=Path(args.repo_path),
            head_sha=args.head_sha,
            base_sha=args.base_sha,
            changed_files=changed_list,
            fail_on_severity=args.fail_on,
            strict_checks=args.strict_checks,
            baseline_findings_file=base_file,
            head_findings_file=head_file,
            verifications_file=verif_file,
            output_format=args.format,
            output_file=out_file,
            pr_number=args.pr_number,
            failed_checks=args.failed_checks,
        )

        if args.format == "markdown":
            print(payload["summary_markdown"])
        elif args.format == "text":
            print(f"Red Mercury Security Gate Verdict: {payload['gate_status']} (Exit Code {exit_code})")
            print(f"New: {payload['metrics']['new_findings']} | Resolved: {payload['metrics']['resolved_findings']} | Regressed: {payload['metrics']['regressed_findings']}")
            if payload['failed_checks']:
                print("Failed Checks:")
                for fc in payload['failed_checks']:
                    print(f"  - {fc}")
            if payload['unavailable_checks']:
                print("Unavailable Checks:")
                for uc in payload['unavailable_checks']:
                    print(f"  - {uc}")
        elif args.format == "sarif":
            sarif_data = payload.get("sarif") or _generate_sarif_report(Path(args.repo_path), payload.get("head_commit_sha", "HEAD"), payload.get("categorized_findings", []))
            print(json.dumps(sarif_data, indent=2))
        else:
            print(json.dumps(payload, indent=2))

        sys.exit(exit_code)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"Red Mercury Security Gate Execution Error: {exc}", file=sys.stderr)
        try:
            out_path = None
            for i, arg in enumerate(sys.argv):
                if arg in ("--output-file", "--output-report") and i + 1 < len(sys.argv):
                    out_path = Path(sys.argv[i + 1])
                    break
            if out_path:
                out_path.parent.mkdir(parents=True, exist_ok=True)
                err_payload = {
                    "schema_version": "1.0.0",
                    "gate_status": "ERROR",
                    "exit_code": 1,
                    "gate_passed": False,
                    "error": str(exc),
                    "failed_checks": [f"Internal script exception: {type(exc).__name__}: {str(exc)}"],
                    "metrics": {
                        "new_findings": 0,
                        "resolved_findings": 0,
                        "regressed_findings": 0,
                        "unchanged_findings": 0,
                        "verified_fixes": 0,
                        "failed_checks": 1,
                        "unavailable_checks": 0,
                    },
                    "summary_markdown": f"### 🛡️ Red Mercury — Internal Execution Exception\n\n❌ **Gate Execution Error:** `{type(exc).__name__}: {str(exc)}`",
                }
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(err_payload, f, indent=2)
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
