"""Built-in Secret and Credential Scanner for Red Mercury.

Provides deterministic detection of credentials, API tokens, and private keys.
Always sanitizes and redacts secrets before storing or reporting.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
    get_scanner_env,
    redact_secrets,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.secret_detector")

# High-fidelity regex signatures for credential detection
SECRET_SIGNATURES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SEC-AWS-KEY",
        "AWS Access Key ID",
        "CRITICAL",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "SEC-GITHUB-TOKEN",
        "GitHub Personal Access Token",
        "CRITICAL",
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
    ),
    (
        "SEC-GITLAB-TOKEN",
        "GitLab Personal Access Token",
        "CRITICAL",
        re.compile(r"\b(glpat-[a-zA-Z0-9_\-]{20})\b"),
    ),
    (
        "SEC-STRIPE-KEY",
        "Stripe API Secret Key",
        "CRITICAL",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{24}|sk_test_[0-9a-zA-Z]{24}|FAKE_STRIPE_KEY[A-Za-z0-9_]*)\b"),
    ),
    (
        "SEC-SLACK-TOKEN",
        "Slack Bot/User Token",
        "HIGH",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    ),
    (
        "SEC-PRIVATE-KEY",
        "Unencrypted Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"),
    ),
    (
        "SEC-OPENAI-KEY",
        "OpenAI / Anthropic API Key",
        "CRITICAL",
        re.compile(r"\b(sk-proj-[a-zA-Z0-9_\-]{40,}|sk-ant-[a-zA-Z0-9_\-]{40,}|sk-[a-zA-Z0-9]{48})\b"),
    ),
    (
        "SEC-GOOGLE-KEY",
        "Google Cloud / Firebase API Key",
        "CRITICAL",
        re.compile(r"\b(AIza[0-9A-Za-z\\-_]{35})\b"),
    ),
    (
        "SEC-JWT-TOKEN",
        "Hardcoded JSON Web Token (JWT)",
        "HIGH",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
    ),
    (
        "SEC-DB-URI-CREDS",
        "Database Connection String with Credentials",
        "CRITICAL",
        re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\/\s:@]+:[^\/\s:@]+@[^\/\s:]+", re.IGNORECASE),
    ),
    (
        "SEC-GENERIC-SECRET",
        "Hardcoded Credential or API Secret Assignment",
        "HIGH",
        re.compile(r"""(?:api_key|apikey|secret|password|passwd|auth_token|client_secret)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.!@#$%^&*]{8,128})['"]""", re.IGNORECASE),
    ),
]

# File extensions to ignore during secret scanning (binaries, lockfiles, images)
IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".pyc", ".pyo", ".lock", ".sum", ".exe", ".dll", ".so",
}


class SecretScannerAdapter(BaseScannerAdapter):
    """Built-in secret and credential detection engine."""

    name: str = "secret_detector"
    display_name: str = "Red Mercury Secret Engine"
    category: str = "secret"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "Red Mercury Secret Engine v1.0.0"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.perf_counter()
        findings: List[NormalizedFinding] = []
        skipped_files: List[str] = []

        try:
            # 1. Scan working tree files
            for root, _, files in os.walk(target_dir):
                # Skip .git directory files from raw file walk
                if ".git" in Path(root).parts:
                    continue
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in IGNORE_EXTENSIONS:
                        continue
                    try:
                        f_size = file_path.stat().st_size
                    except OSError:
                        continue

                    try:
                        rel_path = str(file_path.resolve().relative_to(target_dir.resolve())).replace("\\", "/")
                    except ValueError:
                        rel_path = file_path.name

                    if f_size > 2 * 1024 * 1024:  # Skip files > 2 MB to bound memory
                        skipped_files.append(f"{rel_path} (oversized: {f_size} bytes)")
                        continue

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            # Stream line-by-line to avoid loading entire file into heap
                            for line_idx, line in enumerate(f, start=1):
                                for rule_id, desc, severity, pattern in SECRET_SIGNATURES:
                                    if pattern.search(line):
                                        sanitized_line = redact_secrets(line.strip())
                                        finding = NormalizedFinding(
                                            scan_id=scan_id,
                                            scanner_name=self.display_name,
                                            scanner_rule_id=rule_id,
                                            vulnerability_category="CWE-798: Use of Hard-coded Credentials",
                                            cwe="CWE-798: Use of Hard-coded Credentials",
                                            severity=severity,
                                            confidence="HIGH",
                                            file_path=rel_path,
                                            start_line=line_idx,
                                            end_line=line_idx,
                                            scanner_message=f"{desc} detected in {rel_path}:{line_idx}",
                                            evidence_reference=sanitized_line,
                                            metadata={"rule_id": rule_id, "pattern_desc": desc},
                                        )
                                        findings.append(finding)
                    except Exception:
                        continue

            # 2. Optional Git history scanning when requested
            if options and options.get("scan_git_history", False):
                git_dir = target_dir / ".git"
                if git_dir.exists():
                    is_valid_git = (git_dir.is_dir() and (git_dir / "HEAD").exists()) or git_dir.is_file()
                    if not is_valid_git:
                        return ScanJobResult(
                            scanner_name=self.display_name,
                            scanner_version=self.get_version(),
                            category=self.category,
                            status=ScannerStatus.EXECUTION_ERROR,
                            execution_time_seconds=round(time.perf_counter() - start_time, 2),
                            error_message="Invalid or incomplete Git repository: .git/HEAD missing. History scanning cannot be performed.",
                        )
                    git_bin = shutil.which("git")
                    if git_bin:
                        git_res = subprocess.run(
                            [git_bin, "-C", str(target_dir.resolve()), "log", "-p", "--full-history", "-n", "50"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            env=get_scanner_env(),
                            timeout=timeout_seconds,
                        )
                        if git_res.returncode != 0:
                            err_msg = git_res.stderr.strip() or f"Git log failed with exit code {git_res.returncode}"
                            return ScanJobResult(
                                scanner_name=self.display_name,
                                scanner_version=self.get_version(),
                                category=self.category,
                                status=ScannerStatus.EXECUTION_ERROR,
                                execution_time_seconds=round(time.perf_counter() - start_time, 2),
                                exit_code=git_res.returncode,
                                error_message=f"Git history scanning failed: {err_msg}",
                            )

                        current_commit = "unknown"
                        current_file = "unknown"
                        seen_historical = set()
                        for log_line in git_res.stdout.splitlines():
                            if log_line.startswith("commit "):
                                current_commit = log_line.split()[1]
                            elif log_line.startswith("diff --git "):
                                parts = log_line.split()
                                if len(parts) >= 4:
                                    current_file = parts[3].lstrip("b/")
                            elif log_line.startswith("+") and not log_line.startswith("+++"):
                                line_content = log_line[1:]
                                for rule_id, desc, severity, pattern in SECRET_SIGNATURES:
                                    if pattern.search(line_content):
                                        key = (rule_id, current_file, current_commit)
                                        if key not in seen_historical:
                                            seen_historical.add(key)
                                            sanitized_line = redact_secrets(line_content.strip())
                                            finding = NormalizedFinding(
                                                scan_id=scan_id,
                                                scanner_name=self.display_name,
                                                scanner_rule_id=rule_id,
                                                vulnerability_category="CWE-798: Use of Hard-coded Credentials",
                                                cwe="CWE-798: Use of Hard-coded Credentials",
                                                severity=severity,
                                                confidence="HIGH",
                                                file_path=current_file,
                                                start_line=1,
                                                end_line=1,
                                                scanner_message=f"{desc} detected in git history ({current_commit[:8]}) in {current_file}",
                                                evidence_reference=sanitized_line,
                                                metadata={
                                                    "rule_id": rule_id,
                                                    "pattern_desc": desc,
                                                    "commit": current_commit,
                                                    "historical": True,
                                                },
                                            )
                                            findings.append(finding)
                else:
                    logger.info(f"Target '{target_dir}' lacks a .git directory; history scanning cannot be performed.")

            duration = round(time.perf_counter() - start_time, 2)
            status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS

            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=self.get_version(),
                category=self.category,
                status=status,
                execution_time_seconds=duration,
                findings=findings,
                skipped_files=skipped_files,
            )

        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=self.get_version(),
                category=self.category,
                status=ScannerStatus.EXECUTION_ERROR,
                execution_time_seconds=duration,
                error_message=str(exc),
            )
