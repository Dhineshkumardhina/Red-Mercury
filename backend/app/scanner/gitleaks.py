"""Gitleaks adapter for detecting exposed secrets and credentials."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
    get_scanner_env,
    redact_secrets,
    resolve_tool_binary,
)
from ..core.logging import get_logger

logger = get_logger("redmercury.scanner.gitleaks")


class GitleaksScannerAdapter(BaseScannerAdapter):
    """Adapter for Gitleaks: Standalone SAST secret scanner."""

    name: str = "gitleaks"
    display_name: str = "Gitleaks Secret Scanner"
    category: str = "secret"

    def is_available(self) -> bool:
        return resolve_tool_binary("gitleaks") is not None

    def get_version(self) -> Optional[str]:
        bin_path = resolve_tool_binary("gitleaks")
        if not bin_path:
            return None
        try:
            res = subprocess.run(
                [bin_path, "version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_scanner_env(),
                timeout=5,
            )
            return res.stdout.strip()
        except Exception:
            return None

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        bin_path = resolve_tool_binary("gitleaks")
        if not bin_path:
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=None,
                category=self.category,
                status=ScannerStatus.TOOL_NOT_INSTALLED,
                execution_time_seconds=0.0,
                error_message="Gitleaks binary is not installed on this system. Download from: https://github.com/gitleaks/gitleaks",
            )

        start_time = time.perf_counter()
        version_str = self.get_version()

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_report:
            report_path = Path(tmp_report.name)

        try:
            scan_git_history = options.get("scan_git_history", True) if options else True
            git_dir = target_dir / ".git"
            mode = "dir"
            history_scan_status = None

            if scan_git_history:
                if not git_dir.exists():
                    # Preserve compatibility with repositories that do not contain a .git directory
                    history_scan_status = "unavailable_no_git_directory"
                    mode = "dir"
                    logger.info(f"Target '{target_dir}' lacks a .git directory; falling back to directory scan.")
                else:
                    # Validate that .git is not corrupted/empty
                    is_valid_git = (git_dir.is_dir() and (git_dir / "HEAD").exists()) or git_dir.is_file()
                    if not is_valid_git:
                        return ScanJobResult(
                            scanner_name=self.display_name,
                            scanner_version=version_str,
                            category=self.category,
                            status=ScannerStatus.EXECUTION_ERROR,
                            execution_time_seconds=round(time.perf_counter() - start_time, 2),
                            error_message="Invalid or incomplete Git repository: .git/HEAD missing. History scanning cannot be performed.",
                        )
                    mode = "git"

            # Gitleaks command: git vs dir mode (Gitleaks v8 uses 'detect', with '--no-git' for filesystem directories)
            if mode == "git":
                args = [
                    bin_path,
                    "detect",
                    "--source", str(target_dir.resolve()),
                    "--report-format", "json",
                    "--report-path", str(report_path.resolve()),
                    "--no-banner",
                ]
            else:
                args = [
                    bin_path,
                    "detect",
                    "--no-git",
                    "--source", str(target_dir.resolve()),
                    "--report-format", "json",
                    "--report-path", str(report_path.resolve()),
                    "--no-banner",
                ]

            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=get_scanner_env(),
                timeout=timeout_seconds,
            )
            duration = round(time.perf_counter() - start_time, 2)

            # Gitleaks exit codes: 0 = no leaks, 1 = leaks found
            if result.returncode not in (0, 1):
                err = result.stderr.strip() or f"Gitleaks exited with code {result.returncode}"
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=duration,
                    exit_code=result.returncode,
                    error_message=err,
                )

            normalized: List[NormalizedFinding] = []
            if report_path.exists() and report_path.stat().st_size > 0:
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        raw_data = json.load(f)

                    for item in raw_data:
                        rule_id = item.get("RuleID", "exposed-secret")
                        desc = item.get("Description", "Potential exposed secret")
                        file_abs = item.get("File", "")
                        try:
                            rel_path = str(Path(file_abs).resolve().relative_to(target_dir.resolve())).replace("\\", "/")
                        except ValueError:
                            rel_path = Path(file_abs).name

                        start_line = item.get("StartLine", 1)
                        end_line = item.get("EndLine", start_line)
                        raw_match = item.get("Match", "")
                        sanitized_match = redact_secrets(raw_match)
                        commit_hash = item.get("Commit")

                        msg = f"{desc} in {rel_path}:{start_line}"
                        if commit_hash:
                            msg += f" (commit {commit_hash[:8]})"

                        finding = NormalizedFinding(
                            scan_id=scan_id,
                            scanner_name=self.display_name,
                            scanner_rule_id=rule_id,
                            vulnerability_category="CWE-798: Use of Hard-coded Credentials",
                            cwe="CWE-798: Use of Hard-coded Credentials",
                            severity="CRITICAL",
                            confidence="HIGH",
                            file_path=rel_path,
                            start_line=start_line,
                            end_line=end_line,
                            scanner_message=msg,
                            evidence_reference=sanitized_match,
                            metadata={
                                "rule_id": rule_id,
                                "entropy": item.get("Entropy", 0),
                                "commit": commit_hash,
                                "author": item.get("Author"),
                                "date": item.get("Date"),
                            },
                        )
                        normalized.append(finding)
                except Exception as parse_exc:
                    return ScanJobResult(
                        scanner_name=self.display_name,
                        scanner_version=version_str,
                        category=self.category,
                        status=ScannerStatus.EXECUTION_ERROR,
                        execution_time_seconds=duration,
                        exit_code=result.returncode,
                        error_message=f"Failed to parse Gitleaks report: {parse_exc}",
                    )

            # Guard against silently masking failures:
            # If exit code was 1 (indicating leaks were found), but zero findings could be extracted,
            # or stderr contained fatal errors, treat as execution error rather than clean result.
            if result.returncode == 1 and not normalized:
                err_msg = result.stderr.strip() or "Gitleaks reported leaks (code 1) but report produced zero findings."
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=duration,
                    exit_code=result.returncode,
                    error_message=err_msg,
                )

            status = ScannerStatus.SUCCESS if normalized else ScannerStatus.NO_FINDINGS

            job_result = ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=status,
                execution_time_seconds=duration,
                findings=normalized,
            )
            return job_result

        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=ScannerStatus.TIMEOUT,
                execution_time_seconds=duration,
                error_message=f"Gitleaks scan timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=ScannerStatus.EXECUTION_ERROR,
                execution_time_seconds=duration,
                error_message=str(exc),
            )
        finally:
            if report_path.exists():
                try:
                    report_path.unlink()
                except OSError:
                    pass
