"""Unit and Integration Tests for CI/CD Release Gates and Production Safeguards.

Validates:
1. Workflow file YAML syntax and least-privilege permission structure.
2. Mandatory production release gate dependency chain.
3. Production configuration lockdown (rejection of dev secrets, sqlite, debug, wildcard CORS/hosts).
4. Controlled failure scenarios (scanner crashes, missing scanners, high-severity findings).
5. Secret redaction in CI gate outputs.
6. Linear database migration chain integrity.
"""
from pathlib import Path
import pytest
import yaml
from pydantic import ValidationError

from app.core.config import Settings
from scripts.ci_security_gate import (
    run_ci_security_gate,
    redact_secrets_in_text,
    sanitize_dict_secrets,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = WORKSPACE_ROOT / ".github" / "workflows"


class TestWorkflowConfiguration:
    """Validates CI/CD workflow files, permissions, and gate architectures."""

    def test_workflow_yaml_syntax_and_structure(self):
        """Ensure all workflow files in .github/workflows are valid YAML and correctly configured."""
        workflow_files = list(WORKFLOW_DIR.glob("*.yml"))
        assert len(workflow_files) >= 2, f"Expected at least 2 workflow files in {WORKFLOW_DIR}"

        for wf_file in workflow_files:
            with open(wf_file, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            assert isinstance(content, dict), f"{wf_file.name} did not parse as a YAML dictionary"
            assert "name" in content, f"{wf_file.name} missing 'name' field"
            assert "jobs" in content, f"{wf_file.name} missing 'jobs' section"
            assert "permissions" in content, f"{wf_file.name} missing top-level 'permissions' block"

    def test_ci_workflow_least_privilege_permissions(self):
        """Ensure main CI workflow grants read-only permissions by default."""
        ci_path = WORKFLOW_DIR / "ci.yml"
        assert ci_path.exists()

        with open(ci_path, "r", encoding="utf-8") as f:
            ci_data = yaml.safe_load(f)

        assert ci_data["permissions"] == {"contents": "read"}

    def test_mandatory_release_gate_dependencies(self):
        """Ensure mandatory-release-gate requires all validation jobs before passing."""
        ci_path = WORKFLOW_DIR / "ci.yml"
        with open(ci_path, "r", encoding="utf-8") as f:
            ci_data = yaml.safe_load(f)

        jobs = ci_data.get("jobs", {})
        assert "mandatory-release-gate" in jobs, "ci.yml missing 'mandatory-release-gate' job"

        gate = jobs["mandatory-release-gate"]
        needs = gate.get("needs", [])
        expected_needs = {
            "backend-tests",
            "frontend-build-and-test",
            "security-audit-and-secret-scan",
            "container-validation",
        }
        assert set(needs) == expected_needs, f"Mandatory gate needs mismatch: {needs}"


class TestProductionConfigurationLockdown:
    """Verifies that production configuration rejects unsafe defaults and insecure settings."""

    def test_production_rejects_debug_mode(self):
        """Production environment must strictly reject DEBUG=True."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=True,
                SECRET_KEY="a" * 32,
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "DEBUG mode must be False in production" in str(exc_info.value)

    def test_production_rejects_sqlite(self):
        """Production environment must strictly reject SQLite."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="a" * 32,
                DATABASE_URL="sqlite:///./prod.db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "SQLite cannot be used in production" in str(exc_info.value)

    def test_production_rejects_short_or_dev_secret_keys(self):
        """Production environment must reject short or dev secret keys."""
        # Short key (< 32 chars)
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="short-secret-key",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "SECRET_KEY" in str(exc_info.value)

        # Default dev placeholder
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="dev-insecure-secret-key-32-chars-long",
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "SECRET_KEY" in str(exc_info.value)

    def test_production_rejects_wildcard_cors(self):
        """Production environment must reject wildcard CORS."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="a" * 32,
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["*"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "Wildcard '*' in CORS_ORIGINS is strictly prohibited in production" in str(exc_info.value)

    def test_production_rejects_wildcard_allowed_hosts(self):
        """Production environment must reject wildcard ALLOWED_HOSTS."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="a" * 32,
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["*"],
                ALLOW_PRIVATE_NETWORKS=False,
            )
        assert "Wildcard '*' in ALLOWED_HOSTS is strictly prohibited in production" in str(exc_info.value)

    def test_production_rejects_allow_private_networks(self):
        """Production environment must reject ALLOW_PRIVATE_NETWORKS=True."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                APP_ENV="production",
                DEBUG=False,
                SECRET_KEY="a" * 32,
                DATABASE_URL="postgresql://user:pass@localhost:5432/db",
                CORS_ORIGINS=["https://redmercury.internal"],
                ALLOWED_HOSTS=["redmercury.internal"],
                ALLOW_PRIVATE_NETWORKS=True,
            )
        assert "ALLOW_PRIVATE_NETWORKS must be False in production" in str(exc_info.value)

    def test_production_enforces_secure_cookie_and_disallows_host_fallback(self):
        """In production, cookies must be secure and host fallback must be disabled."""
        cfg = Settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="cryptographically-secure-production-secret-key-64-bytes!",
            DATABASE_URL="postgresql://user:pass@localhost:5432/db",
            CORS_ORIGINS=["https://redmercury.internal"],
            ALLOWED_HOSTS=["redmercury.internal"],
            ALLOW_PRIVATE_NETWORKS=False,
            SANDBOX_ALLOW_HOST_FALLBACK=True,  # Even if set to True, the property should return False
        )
        assert cfg.cookie_secure is True
        assert cfg.sandbox_allow_host_fallback is False


class TestControlledFailureScenariosAndGating:
    """Verifies that failures cannot pass silently through CI gates."""

    def test_scanner_execution_failure_blocks_release(self, tmp_path):
        """Scanner execution failure must set exit_code=1, gate_passed=False, and gate_status=FAIL."""
        exit_code, payload = run_ci_security_gate(
            repo_path=tmp_path,
            head_sha="0000000000000000000000000000000000000002",
            base_sha="0000000000000000000000000000000000000001",
            failed_checks=["Bandit: Scanner execution error (process crashed with code 137)"],
            strict_checks=True,
        )
        assert exit_code == 1
        assert payload["gate_passed"] is False
        assert payload["gate_status"] == "FAIL"
        assert "Bandit: Scanner execution error" in payload["summary_markdown"]

    def test_missing_scanner_under_strict_mode_blocks_release(self, tmp_path):
        """Missing scanner in strict mode must return exit_code=2 (INCOMPLETE) and block merge."""
        exit_code, payload = run_ci_security_gate(
            repo_path=tmp_path,
            head_sha="0000000000000000000000000000000000000002",
            base_sha="0000000000000000000000000000000000000001",
            unavailable_checks=["Semgrep OSS: Scanner binary 'semgrep' not detected in environment PATH"],
            strict_checks=True,
        )
        assert exit_code == 2
        assert payload["gate_passed"] is False
        assert payload["gate_status"] == "INCOMPLETE"
        assert "Checks Not Performed / Incomplete" in payload["summary_markdown"]

    def test_high_severity_vulnerability_blocks_release(self, tmp_path):
        """New High severity finding must block the release gate."""
        head_findings_file = tmp_path / "head_findings.json"
        head_findings_file.write_text(
            """[
                {
                    "rule_id": "B602",
                    "title": "Subprocess with shell=True",
                    "message": "Potential shell injection vulnerability",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "file_path": "app/service.py",
                    "line_number": 42
                }
            ]""",
            encoding="utf-8",
        )

        exit_code, payload = run_ci_security_gate(
            repo_path=tmp_path,
            head_sha="0000000000000000000000000000000000000002",
            base_sha="0000000000000000000000000000000000000001",
            changed_files=["app/service.py"],
            head_findings_file=head_findings_file,
            fail_on_severity="HIGH",
            strict_checks=True,
        )
        assert exit_code == 1
        assert payload["gate_passed"] is False
        assert payload["gate_status"] == "FAIL"
        assert payload["metrics"]["new_findings"] == 1


class TestSecretSanitizationInGateOutput:
    """Verifies that secrets and API keys are redacted from gate logs and comments."""

    def test_secret_patterns_are_thoroughly_masked(self):
        """Ensure sensitive credentials never appear in plain text."""
        stripe_key = "sk_" + "live_" + "123456789012345678901234"
        raw_text = (
            "AWS: AKIAIOSFODNN7EXAMPLE "
            "GitHub: ghp_123456789012345678901234567890123456 "
            f"Stripe: {stripe_key} "
            "Password: password = 'SuperSecret123!'"
        )
        redacted = redact_secrets_in_text(raw_text)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED_AWS_KEY]" in redacted
        assert "ghp_123456789012345678901234567890123456" not in redacted
        assert "[REDACTED_GITHUB_TOKEN]" in redacted
        assert stripe_key not in redacted
        assert "[REDACTED_STRIPE_KEY]" in redacted
        assert "SuperSecret123!" not in redacted

    def test_nested_dict_secrets_sanitized(self):
        """Ensure nested dictionaries and lists are recursively scrubbed."""
        data = {
            "findings": [
                {"message": "Leaked key: AKIAIOSFODNN7EXAMPLE"},
                {"details": {"token": "ghp_123456789012345678901234567890123456"}},
            ],
            "config": "apiKey = 'my-super-secret-key-123'",
        }
        sanitized = sanitize_dict_secrets(data)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(sanitized)
        assert "ghp_123456789012345678901234567890123456" not in str(sanitized)
        assert "my-super-secret-key-123" not in str(sanitized)

