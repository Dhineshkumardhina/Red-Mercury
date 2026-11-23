"""Execution Engine for Scanners and Tests in Isolated Workspaces.

Enforces:
1. Re-running relevant static analysis rules.
2. Executing existing unit and regression tests with subprocess bounding.
3. Timeouts and memory-conscious execution.
4. Capturing test failures, timeouts, and execution errors without leaking secrets.
"""
import ast
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
from ..core.config import settings
from ..scanner.base import NormalizedFinding, ScannerStatus
from ..scanner.registry import scanner_registry


# Prohibited call names and modules in untrusted test files to prevent host execution
DISALLOWED_CALL_NAMES = {
    "os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "pty.spawn", "socket.socket", "socket.create_connection",
    "system", "popen", "Popen",
    "eval", "exec", "__import__", "compile",
    "shutil.rmtree",
}

DISALLOWED_MODULES = {
    "subprocess", "pty", "socket", "ctypes", "http.client", "urllib.request",
}


def inspect_test_safety(workspace_dir: Path, target_path: Optional[Path] = None) -> Optional[str]:
    """Scan test and configuration files for high-risk system commands that violate the runner sandbox policy.
    
    Uses AST parsing to distinguish actual executable system calls from string literals
    (such as benign exploit payload test data). Inspects conftest.py, test suites, and fixtures.
    """
    files_to_check: List[Path] = []
    if target_path and target_path.is_file():
        files_to_check.append(target_path)
    else:
        for p in workspace_dir.rglob("*.py"):
            lower_name = p.name.lower()
            # Check test suites, conftest fixtures, setup scripts, and test directory files
            if p.is_file() and (
                "test" in lower_name
                or lower_name == "conftest.py"
                or lower_name == "setup.py"
                or "tests" in [part.lower() for part in p.parts]
            ):
                files_to_check.append(p)

    for test_file in files_to_check:
        try:
            content = test_file.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    # Check imports
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            base_mod = alias.name.split(".")[0]
                            if base_mod in DISALLOWED_MODULES:
                                return (
                                    f"Security policy violation in test '{test_file.name}': "
                                    f"Detected prohibited module import ({alias.name}). "
                                    f"Untrusted test suites cannot access raw network, ctypes, or subprocesses."
                                )
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            base_mod = node.module.split(".")[0]
                            if base_mod in DISALLOWED_MODULES:
                                return (
                                    f"Security policy violation in test '{test_file.name}': "
                                    f"Detected prohibited module import from {node.module}. "
                                    f"Untrusted test suites cannot access raw network, ctypes, or subprocesses."
                                )

                    # Check function calls
                    if isinstance(node, ast.Call):
                        call_name = ""
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                            call_name = f"{node.func.value.id}.{node.func.attr}"
                        elif isinstance(node.func, ast.Name):
                            call_name = node.func.id

                        if call_name in DISALLOWED_CALL_NAMES or call_name.startswith("subprocess."):
                            rel_name = test_file.name
                            return (
                                f"Security policy violation in test '{rel_name}': "
                                f"Detected prohibited call ({call_name}). "
                                f"Untrusted test suites cannot invoke host shell or subprocess commands."
                            )
            except SyntaxError:
                # If syntax error in test file, fallback to call pattern regex
                if re.search(
                    r"\b(os\.system|os\.popen|subprocess\.(Popen|run|call)|socket\.socket|eval|exec|__import__)\s*\(",
                    content,
                ):
                    return (
                        f"Security policy violation in test '{test_file.name}': "
                        f"Detected prohibited system call invocation. "
                        f"Untrusted test suites cannot invoke host shell or subprocess commands."
                    )
        except Exception as e:
            return f"Failed to inspect test safety for {test_file.name}: {str(e)}"

    return None



@dataclass
class TestExecutionOutcome:
    test_suite_name: str
    status: str  # passed, failed, timeout, skipped, error
    passed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    execution_time_seconds: float = 0.0
    output_log: str = ""
    error_message: Optional[str] = None


@dataclass
class VerificationChecksOutcome:
    baseline_findings: List[NormalizedFinding] = field(default_factory=list)
    patched_findings: List[NormalizedFinding] = field(default_factory=list)
    scanners_executed: List[str] = field(default_factory=list)
    scanner_metadata: Dict[str, Any] = field(default_factory=dict)
    test_outcomes: List[TestExecutionOutcome] = field(default_factory=list)
    execution_errors: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)


def run_scanners_on_directory(
    target_dir: Path,
    scanner_names: Optional[List[str]] = None,
    timeout_seconds: int = 30,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[List[NormalizedFinding], Dict[str, Any], List[str]]:
    """Execute configured scanners against a directory and return normalized findings."""
    findings: List[NormalizedFinding] = []
    metadata: Dict[str, Any] = {}
    errors: List[str] = []

    available_adapters = scanner_registry.list_all()
    if scanner_names:
        adapters = [a for a in available_adapters if a.name in scanner_names]
        unregistered = [name for name in scanner_names if not any(a.name == name for a in available_adapters)]
        for name in unregistered:
            errors.append(f"Scanner '{name}' is not registered in this environment.")
    else:
        adapters = available_adapters

    for adapter in adapters:
        meta_entry = {
            "name": adapter.name,
            "display_name": adapter.display_name,
            "category": adapter.category,
            "is_available": adapter.is_available(),
            "version": adapter.get_version(),
        }
        metadata[adapter.name] = meta_entry

        if not adapter.is_available():
            if scanner_names and adapter.name in scanner_names:
                errors.append(f"{adapter.display_name} is not installed or available in this environment.")
            continue

        try:
            job_result = adapter.scan(
                target_dir=target_dir,
                scan_id="verify_scan",
                timeout_seconds=timeout_seconds,
                options=options,
            )
            findings.extend(job_result.findings)
            meta_entry["status"] = job_result.status.value
            meta_entry["execution_time"] = job_result.execution_time_seconds

            if job_result.status in (ScannerStatus.EXECUTION_ERROR, ScannerStatus.TIMEOUT):
                errors.append(f"{adapter.display_name}: {job_result.error_message or 'Scanner execution failed'}")
        except Exception as e:
            errors.append(f"Failed executing scanner {adapter.name}: {str(e)}")

    return findings, metadata, errors


from .sandbox import SandboxConfig, run_isolated_verification_command


def run_pytest_in_workspace(
    workspace_dir: Path,
    test_target: Optional[str] = None,
    timeout_seconds: int = 30,
    allow_host_fallback: Optional[bool] = None,
    sandbox_config: Optional[SandboxConfig] = None,
) -> TestExecutionOutcome:
    """Execute pytest within an isolated sandbox environment adhering to strict security invariants."""
    # Determine test arguments
    cmd_args: List[str] = []

    # Check if explicit test target was provided or project-wide test discovery should run
    if test_target is not None:
        if not isinstance(test_target, str) or not test_target.strip():
            return TestExecutionOutcome(
                test_suite_name="invalid_target",
                status="error",
                error_message="Invalid test target: test target cannot be empty or whitespace-only.",
            )

        if "\x00" in test_target:
            return TestExecutionOutcome(
                test_suite_name="invalid_target",
                status="error",
                error_message="Invalid test target: null bytes are not permitted.",
            )

        clean_target = test_target.strip()
        if clean_target.startswith("-"):
            return TestExecutionOutcome(
                test_suite_name="invalid_target",
                status="error",
                error_message="Command option injection attempt rejected in test target.",
            )

        resolved_ws = workspace_dir.resolve()
        posix_rel = clean_target.replace("\\", "/")
        target_parts = [part for part in posix_rel.split("/") if part and part != "."]
        if (
            clean_target.startswith(("/", "\\"))
            or posix_rel.startswith("//")
            or re.match(r"^[A-Za-z]:", clean_target)
            or ".." in target_parts
            or not target_parts
        ):
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="error",
                error_message="Path traversal detected in test target: target must be a safe relative workspace path.",
            )

        raw_target = resolved_ws / posix_rel
        if raw_target.is_symlink():
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="error",
                error_message="Path traversal detected in test target: symbolic link targets are not permitted.",
            )

        target_path = raw_target.resolve()
        try:
            target_path.relative_to(resolved_ws)
        except ValueError:
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="error",
                error_message="Path traversal detected in test target: resolved path escapes workspace boundary.",
            )

        if not target_path.exists():
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="skipped",
                error_message="Specified test target does not exist in workspace.",
            )
        cmd_args = ["--", "/".join(target_parts)]
    else:
        # Check if any tests directory exists
        has_tests = (
            (workspace_dir / "tests").is_dir()
            or any(workspace_dir.glob("test_*.py"))
            or any(workspace_dir.glob("*_test.py"))
        )
        if not has_tests:
            return TestExecutionOutcome(
                test_suite_name="project_tests",
                status="skipped",
                output_log="No unit tests found in workspace.",
            )

    # Pre-execution safety inspection to block dangerous commands in untrusted tests
    target_file_to_check = target_path if test_target else None
    safety_violation = inspect_test_safety(workspace_dir=workspace_dir, target_path=target_file_to_check)
    if safety_violation:
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="error",
            error_message=safety_violation,
            output_log=safety_violation,
        )

    # Resolve sandbox configuration
    cfg = sandbox_config or SandboxConfig(
        timeout_seconds=timeout_seconds,
        allow_host_fallback=allow_host_fallback
        if allow_host_fallback is not None
        else settings.sandbox_allow_host_fallback,
    )

    # Execute inside isolated sandbox (Docker unprivileged container with network=none, or fail-closed)
    returncode, stdout, stderr, is_timeout, error_msg = run_isolated_verification_command(
        workspace_dir=workspace_dir,
        cmd_args=cmd_args,
        config=cfg,
    )

    if is_timeout:
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="timeout",
            error_message=error_msg or f"Test execution exceeded {timeout_seconds}s timeout limit.",
            output_log=(stdout + "\n" + stderr)[:4000],
        )

    if returncode == -1 and error_msg:
        # Sandbox isolation unavailable (fail-closed) or container startup error
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="error",
            error_message=error_msg,
            output_log=error_msg,
        )

    output = (stdout or "") + "\n" + (stderr or "")

    # Parse pytest output
    passed = 0
    failed = 0
    skipped = 0
    m_p = re.findall(r'(\d+)\s+passed', output)
    m_f = re.findall(r'(\d+)\s+failed', output)
    m_s = re.findall(r'(\d+)\s+skipped', output)
    if m_p:
        passed = int(m_p[-1])
    if m_f:
        failed = int(m_f[-1])
    if m_s:
        skipped = int(m_s[-1])

    if returncode in (125, 126, 127) or (passed == 0 and failed == 0 and returncode != 0):
        status = "error"
        err_text = error_msg or f"Container or runner execution error (exit code {returncode})"
    else:
        status = "passed" if returncode == 0 else "failed"
        err_text = None if status == "passed" else f"Test run exited with code {returncode}"

    return TestExecutionOutcome(
        test_suite_name=test_target or "project_tests",
        status=status,
        passed_count=passed,
        failed_count=failed,
        skipped_count=skipped,
        output_log=output[:4000],
        error_message=err_text,
    )
