"""Automated Test Suite for Benchmark Framework.

Tests:
1. Benchmark case data models and JSON Schema validation.
2. Dataset deduplication, collision detection, and split leakage protection.
3. Metric calculations (Precision, Recall, FPR, FNR, Inconclusive Rate, RDR, McNemar's test).
4. All seven evaluation test categories (Effective fixes, Ineffective fixes, Partial fixes,
   Functional regressions, Security regressions, False positive findings, Missing evidence, Tool failures).
5. All four comparative verification baselines (SAST alone, Tests alone, AI judge, Red Mercury).
6. Multi-format reporting (JSON, summary CSV, detailed CSV, Markdown).
"""
import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from benchmark.models import (
    BenchmarkCaseDefinition,
    CandidatePatchDefinition,
    BaselineId,
    DatasetSplit,
    GroundTruthLabel,
    SampleExperimentRecord,
    VerificationVerdict,
)
from benchmark.deduplicator import (
    calculate_content_digest,
    validate_dataset_uniqueness_and_splits,
)
from benchmark.metrics import (
    calculate_baseline_metrics,
    compute_mcnemar_test,
    evaluate_correctness,
)
from benchmark.baselines.sast_alone import SastAloneBaseline
from benchmark.baselines.tests_alone import ExistingTestsAloneBaseline
from benchmark.baselines.ai_judge import AiJudgeBaseline
from benchmark.baselines.combined_verifier import RedMercuryCombinedBaseline
from benchmark.reporting import (
    export_csv_detailed_samples,
    export_csv_summary,
    export_json_report,
    generate_markdown_report,
)
from benchmark.runner import load_benchmark_cases


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------
@pytest.fixture
def sample_benchmark_case() -> BenchmarkCaseDefinition:
    return BenchmarkCaseDefinition(
        case_id="TEST-CASE-001",
        origin="synthetic_test",
        cwe_id="CWE-89",
        vulnerability_category="sql_injection",
        description="SQL injection in query authentication",
        source_file="src/auth.py",
        vulnerable_code="def auth(u, p):\n    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n    return query\n",
        baseline_revision="sha256-test-baseline-1234",
        baseline_finding={
            "rule_id": "B608",
            "category": "sql_injection",
            "start_line": 2,
            "severity": "high",
        },
        split=DatasetSplit.DEV.value,
        existing_unit_test="from src.auth import auth\ndef test_auth():\n    assert 'SELECT' in auth('admin', '123')\n",
        targeted_regression_test="from src.auth import auth\ndef test_exploit():\n    assert '\"' not in auth('a\" OR 1=1', 'p')\n",
        candidate_patches=[
            CandidatePatchDefinition(
                patch_id="TP-001",
                patch_type="true_fix",
                ground_truth_label="FIX",
                ground_truth_rationale="Uses parameterized query safely",
                expected_classification="VERIFIED",
                expected_regression_status="RESOLVED_BY_DEFINED_CHECKS",
                unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -2,2 +2,2 @@\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    query = 'SELECT * FROM u WHERE n=?'\n",
                description="Parameterizes query",
            ),
            CandidatePatchDefinition(
                patch_id="TP-002",
                patch_type="cosmetic_evasion",
                ground_truth_label="NON_FIX",
                ground_truth_rationale="Obfuscates string concatenation across variables",
                expected_classification="FAILED",
                expected_regression_status="POTENTIALLY_REGRESSED",
                unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -2,2 +2,3 @@\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    x = 'SELECT * FROM u WHERE n=\"' + u\n+    query = x + '\"'\n",
                description="String concatenation indirection",
            ),
        ],
    )


# -----------------------------------------------------------------------------
# 1. Dataset Loading and Schema Validation Tests
# -----------------------------------------------------------------------------
def test_all_benchmark_cases_exist_and_load_cleanly():
    """Verify that all case JSON files in benchmark/cases load and contain required fields."""
    cases_dir = Path("benchmark/cases")
    cases = load_benchmark_cases(cases_dir)
    assert len(cases) >= 7

    case_ids = [c.case_id for c in cases]
    assert "RS-BENCH-001" in case_ids
    assert "RS-BENCH-002" in case_ids
    assert "RS-BENCH-003" in case_ids
    assert "RS-BENCH-004" in case_ids
    assert "RS-BENCH-005" in case_ids
    assert "RS-BENCH-006" in case_ids
    assert "RS-BENCH-007" in case_ids

    # Verify split partitioning
    dev_cases = [c for c in cases if c.split == "dev"]
    held_out_cases = [c for c in cases if c.split == "held_out"]
    assert len(dev_cases) >= 3
    assert len(held_out_cases) >= 4

    for c in cases:
        assert c.origin != ""
        assert c.cwe_id != ""
        assert c.baseline_revision != ""
        assert len(c.candidate_patches) >= 1
        for p in c.candidate_patches:
            assert p.ground_truth_label in ("FIX", "NON_FIX", "INCONCLUSIVE")
            assert p.ground_truth_rationale != ""
            assert p.unified_diff.startswith("---")


# -----------------------------------------------------------------------------
# 2. Deduplication and Split Integrity Tests
# -----------------------------------------------------------------------------
def test_deduplicator_clean_dataset(sample_benchmark_case):
    """Verify that a clean dataset reports zero collisions or errors."""
    report = validate_dataset_uniqueness_and_splits([sample_benchmark_case])
    assert report.has_errors is False
    assert report.total_cases_analyzed == 1
    assert report.total_patches_analyzed == 2
    assert report.unique_cases == 1
    assert report.unique_patches == 2


def test_deduplicator_detects_case_id_collision(sample_benchmark_case):
    """Verify that duplicate case_id is detected as an error."""
    dup_case = BenchmarkCaseDefinition(
        case_id="TEST-CASE-001",  # Same ID!
        origin="synthetic_test",
        cwe_id="CWE-78",
        vulnerability_category="command_injection",
        description="Different description",
        source_file="src/other.py",
        vulnerable_code="import os\nos.system('ls')\n",
        baseline_revision="hash-different",
        baseline_finding={"rule_id": "B605", "category": "cmd", "start_line": 2},
        split="held_out",
        candidate_patches=[],
    )
    report = validate_dataset_uniqueness_and_splits([sample_benchmark_case, dup_case])
    assert report.has_errors is True
    assert any(i.issue_type == "id_collision" for i in report.issues)


def test_deduplicator_detects_split_leakage(sample_benchmark_case):
    """Verify that identical code or diff in both dev and held_out is flagged as split leakage."""
    leaked_case = BenchmarkCaseDefinition(
        case_id="TEST-CASE-LEAKED",
        origin="synthetic_test",
        cwe_id="CWE-89",
        vulnerability_category="sql_injection",
        description="Leaked copy",
        source_file="src/auth.py",
        vulnerable_code=sample_benchmark_case.vulnerable_code,  # Same vulnerable code!
        baseline_revision="hash-dup",
        baseline_finding=sample_benchmark_case.baseline_finding,
        split="held_out",  # Different split!
        candidate_patches=[],
    )
    report = validate_dataset_uniqueness_and_splits([sample_benchmark_case, leaked_case])
    assert report.has_errors is True
    assert any(i.issue_type == "split_leakage" for i in report.issues)


# -----------------------------------------------------------------------------
# 3. Empirical Metrics and Denominators Tests
# -----------------------------------------------------------------------------
def test_metric_correctness_rules():
    """Verify ground truth evaluation rules across FIX, NON_FIX, and INCONCLUSIVE."""
    assert evaluate_correctness("FIX", "VERIFIED") is True
    assert evaluate_correctness("FIX", "FAILED") is False
    assert evaluate_correctness("FIX", "INCONCLUSIVE") is False

    assert evaluate_correctness("NON_FIX", "FAILED") is True
    assert evaluate_correctness("NON_FIX", "INCONCLUSIVE") is True  # Conservative safe block
    assert evaluate_correctness("NON_FIX", "VERIFIED") is False     # Fatal false positive!

    assert evaluate_correctness("INCONCLUSIVE", "INCONCLUSIVE") is True
    assert evaluate_correctness("INCONCLUSIVE", "VERIFIED") is False
    assert evaluate_correctness("INCONCLUSIVE", "FAILED") is False


def test_calculate_baseline_metrics_accuracy_and_denominators():
    """Verify mathematical calculation of metrics, precision, recall, FPR, FNR, and RDR."""
    samples = [
        # True Positives: GT=FIX, Pred=VERIFIED
        SampleExperimentRecord(
            case_id="C1", patch_id="P1", patch_type="true_fix", split="dev", origin="synth",
            vulnerability_category="sql_injection", baseline_revision="h1", proposed_patch="",
            ground_truth_label="FIX", ground_truth_rationale="", baseline_id="B4",
            baseline_name="Red Mercury", expected_classification="VERIFIED",
            actual_classification="VERIFIED", is_correct=True, runtime_ms=100.0
        ),
        # True Negatives: GT=NON_FIX, Pred=FAILED
        SampleExperimentRecord(
            case_id="C1", patch_id="P2", patch_type="cosmetic_evasion", split="dev", origin="synth",
            vulnerability_category="sql_injection", baseline_revision="h1", proposed_patch="",
            ground_truth_label="NON_FIX", ground_truth_rationale="", baseline_id="B4",
            baseline_name="Red Mercury", expected_classification="FAILED",
            actual_classification="FAILED", is_correct=True, runtime_ms=110.0
        ),
        # True Negatives on regression: GT=NON_FIX, Pred=FAILED
        SampleExperimentRecord(
            case_id="C1", patch_id="P3", patch_type="regressive_fix", split="dev", origin="synth",
            vulnerability_category="sql_injection", baseline_revision="h1", proposed_patch="",
            ground_truth_label="NON_FIX", ground_truth_rationale="", baseline_id="B4",
            baseline_name="Red Mercury", expected_classification="FAILED",
            actual_classification="FAILED", is_correct=True, runtime_ms=120.0
        ),
        # Epistemic Honesty: GT=INCONCLUSIVE, Pred=INCONCLUSIVE
        SampleExperimentRecord(
            case_id="C2", patch_id="P4", patch_type="missing_evidence_case", split="held_out", origin="synth",
            vulnerability_category="access_control", baseline_revision="h2", proposed_patch="",
            ground_truth_label="INCONCLUSIVE", ground_truth_rationale="", baseline_id="B4",
            baseline_name="Red Mercury", expected_classification="INCONCLUSIVE",
            actual_classification="INCONCLUSIVE", is_correct=True, runtime_ms=130.0
        ),
    ]

    m = calculate_baseline_metrics(samples, "B4", "Red Mercury")
    assert m.total_samples == 4
    assert m.true_positives == 1
    assert m.false_positives == 0
    assert m.true_negatives == 3
    assert m.false_negatives == 0
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert m.false_positive_rate == 0.0
    assert m.false_negative_rate == 0.0
    assert m.inconclusive_rate == 0.25
    assert m.regression_detection_rate == 1.0  # Caught 1 of 1 regressive fix
    assert m.correct_classification_rate == 1.0


def test_mcnemar_statistical_test():
    """Verify McNemar's test calculation for paired baseline outcomes."""
    records = [
        # Case 1: B4 correct, B1 wrong
        SampleExperimentRecord(
            case_id="C1", patch_id="P1", patch_type="cosmetic_evasion", split="dev", origin="synth",
            vulnerability_category="sql", baseline_revision="h", proposed_patch="", ground_truth_label="NON_FIX",
            ground_truth_rationale="", baseline_id="B4", baseline_name="Red Mercury", expected_classification="FAILED",
            actual_classification="FAILED", is_correct=True, runtime_ms=10.0
        ),
        SampleExperimentRecord(
            case_id="C1", patch_id="P1", patch_type="cosmetic_evasion", split="dev", origin="synth",
            vulnerability_category="sql", baseline_revision="h", proposed_patch="", ground_truth_label="NON_FIX",
            ground_truth_rationale="", baseline_id="B1", baseline_name="SAST", expected_classification="FAILED",
            actual_classification="VERIFIED", is_correct=False, runtime_ms=10.0
        ),
        # Case 2: B4 correct, B1 wrong
        SampleExperimentRecord(
            case_id="C2", patch_id="P2", patch_type="incomplete_fix", split="dev", origin="synth",
            vulnerability_category="sql", baseline_revision="h", proposed_patch="", ground_truth_label="NON_FIX",
            ground_truth_rationale="", baseline_id="B4", baseline_name="Red Mercury", expected_classification="FAILED",
            actual_classification="FAILED", is_correct=True, runtime_ms=10.0
        ),
        SampleExperimentRecord(
            case_id="C2", patch_id="P2", patch_type="incomplete_fix", split="dev", origin="synth",
            vulnerability_category="sql", baseline_revision="h", proposed_patch="", ground_truth_label="NON_FIX",
            ground_truth_rationale="", baseline_id="B1", baseline_name="SAST", expected_classification="FAILED",
            actual_classification="VERIFIED", is_correct=False, runtime_ms=10.0
        ),
    ]

    chi2, p_val = compute_mcnemar_test(records, "B4", "B1")
    assert chi2 >= 0.0
    assert 0.0 <= p_val <= 1.0


# -----------------------------------------------------------------------------
# 4. Comparative Baselines Tests
# -----------------------------------------------------------------------------
def test_baseline_ai_judge(sample_benchmark_case):
    """Verify AI judge heuristic baseline classifications."""
    b3 = AiJudgeBaseline()
    true_patch = sample_benchmark_case.candidate_patches[0]
    evasive_patch = sample_benchmark_case.candidate_patches[1]

    out_true = b3.evaluate_patch(sample_benchmark_case, true_patch)
    assert out_true.decision == "VERIFIED"
    assert out_true.latency_ms >= 250.0  # Model latency included

    # Evasive patch fools zero-shot LLM (literature reproduction)
    out_evasive = b3.evaluate_patch(sample_benchmark_case, evasive_patch)
    assert out_evasive.decision == "VERIFIED"


def test_baseline_existing_tests_alone(sample_benchmark_case):
    """Verify general unit test baseline passing when patch applies cleanly."""
    b2 = ExistingTestsAloneBaseline()
    true_patch = sample_benchmark_case.candidate_patches[0]

    with patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.verification.runner import TestExecutionOutcome
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_existing.py", status="passed", passed_count=1, failed_count=0
        )
        out = b2.evaluate_patch(sample_benchmark_case, true_patch)
        assert out.decision == "VERIFIED"
        assert out.evidence["passed_count"] == 1


def test_baseline_sast_alone(sample_benchmark_case):
    """Verify SAST alone baseline evaluating rule delta."""
    b1 = SastAloneBaseline()
    true_patch = sample_benchmark_case.candidate_patches[0]

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan:
        from app.scanner.base import NormalizedFinding
        base_f = NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)
        # Baseline scan has B608, patched scan resolves B608
        mock_scan.side_effect = [
            ([base_f], {"bandit": {}}, []),
            ([], {"bandit": {}}, [])
        ]
        out = b1.evaluate_patch(sample_benchmark_case, true_patch)
        assert out.decision == "VERIFIED"


def test_baseline_redmercury_combined_catches_regression(sample_benchmark_case):
    """Verify Red Mercury combined verifier catches regressions and rejects patch."""
    b4 = RedMercuryCombinedBaseline()
    evasive_patch = sample_benchmark_case.candidate_patches[1]

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        base_f = NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)
        # Patched scanner still finds B608
        mock_scan.side_effect = [
            ([base_f], {}, []),
            ([base_f], {}, [])
        ]
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_existing.py", status="passed", passed_count=1, failed_count=0
        )

        out = b4.evaluate_patch(sample_benchmark_case, evasive_patch)
        assert out.decision == "FAILED"
        assert "STILL_PRESENT" in out.evidence["target_classification"]


# -----------------------------------------------------------------------------
# 5. Reporting Engine Tests
# -----------------------------------------------------------------------------
def test_reporting_exports_json_csv_markdown(tmp_path, sample_benchmark_case):
    """Verify that export functions generate valid JSON, CSV, and Markdown reports."""
    from benchmark.models import BenchmarkSuiteSummary

    samples = [
        SampleExperimentRecord(
            case_id="TEST-CASE-001", patch_id="TP-001", patch_type="true_fix", split="dev", origin="synth",
            vulnerability_category="sql_injection", baseline_revision="h1", proposed_patch="",
            ground_truth_label="FIX", ground_truth_rationale="Safe", baseline_id="B4_redmercury_pipeline",
            baseline_name="Red Mercury", expected_classification="VERIFIED",
            actual_classification="VERIFIED", is_correct=True, runtime_ms=150.0
        )
    ]
    metrics = [calculate_baseline_metrics(samples, "B4_redmercury_pipeline", "Red Mercury")]
    summary = BenchmarkSuiteSummary(
        timestamp="2026-10-11T12:00:00Z",
        platform_info={"os": "win32", "platform": "Windows-11", "python_version": "3.14.7"},
        tool_versions={"python": "3.14.7", "bandit": "1.7.0"},
        scanner_config={"timeout": 20},
        total_cases=1,
        total_patches=1,
        dev_patches_count=1,
        held_out_patches_count=0,
        metrics=metrics,
        sample_records=samples,
    )

    # 1. JSON Export
    json_path = tmp_path / "report.json"
    export_json_report(summary, json_path)
    assert json_path.exists()
    loaded_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded_json["total_cases"] == 1
    assert len(loaded_json["metrics"]) == 1

    # 2. Summary CSV Export
    csv_sum_path = tmp_path / "summary.csv"
    export_csv_summary(metrics, csv_sum_path)
    assert csv_sum_path.exists()
    sum_text = csv_sum_path.read_text(encoding="utf-8")
    assert "baseline_id" in sum_text
    assert "Red Mercury" in sum_text

    # 3. Detailed Samples CSV Export
    csv_samp_path = tmp_path / "samples.csv"
    export_csv_detailed_samples(samples, csv_samp_path)
    assert csv_samp_path.exists()
    samp_text = csv_samp_path.read_text(encoding="utf-8")
    assert "TEST-CASE-001" in samp_text
    assert "TP-001" in samp_text

    # 4. Markdown Report Generation
    md_content = generate_markdown_report(summary)
    assert "# Empirical Evaluation of Evidence-Based Security-Fix Verification" in md_content
    assert "Red Mercury" in md_content
    assert "McNemar" in md_content


# -----------------------------------------------------------------------------
# 6. Evaluation Hardening & Edge-Case Failure Mode Tests
# -----------------------------------------------------------------------------
def test_incomplete_fix_rejected_by_targeted_regression_test(sample_benchmark_case):
    """Verify that an incomplete/partial fix passes general tests but fails targeted exploit test."""
    b4 = RedMercuryCombinedBaseline()
    incomplete_patch = CandidatePatchDefinition(
        patch_id="TP-INCOMPLETE",
        patch_type="incomplete_fix",
        ground_truth_label="NON_FIX",
        ground_truth_rationale="Incomplete sanitizer removes only single quotes",
        expected_classification="FAILED",
        expected_regression_status="STILL_PRESENT",
        unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -2,2 +2,3 @@\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    u_clean = u.replace(\"'\", \"\")\n+    query = f'SELECT * FROM u WHERE n=\"{u_clean}\"'\n",
        description="Naive quote stripping",
    )

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        # Scanner: baseline finding B608 resolved by naive replace (AST doesn't see direct raw quote)
        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([], {}, [])
        ]
        # Test runs: 1. Baseline existing test (passed), 2. Patched existing test (passed), 3. Targeted exploit test (FAILED!)
        mock_test.side_effect = [
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_security_regression.py", status="failed", failed_count=1),
        ]

        outcome = b4.evaluate_patch(sample_benchmark_case, incomplete_patch)
        assert outcome.decision == "FAILED"
        assert "Targeted security regression test failed" in outcome.evidence["rationale"]
        assert outcome.evidence["targeted_test_passed"] is False


def test_false_confidence_in_sast_alone_and_unit_tests(sample_benchmark_case):
    """Verify how single-technique baselines suffer from false confidence (False Positives)."""
    b1_sast = SastAloneBaseline()
    b2_tests = ExistingTestsAloneBaseline()
    b4_combined = RedMercuryCombinedBaseline()

    evasive_patch = sample_benchmark_case.candidate_patches[1]  # cosmetic evasion

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        # SAST Alone: Rule disappears because of variable indirection -> Falsely VERIFIED!
        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([], {}, [])  # Rule disappeared
        ]
        out_sast = b1_sast.evaluate_patch(sample_benchmark_case, evasive_patch)
        assert out_sast.decision == "VERIFIED"  # False confidence!

        # Existing Unit Tests Alone: Normal tests pass -> Falsely VERIFIED!
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_existing.py", status="passed", passed_count=1
        )
        out_tests = b2_tests.evaluate_patch(sample_benchmark_case, evasive_patch)
        assert out_tests.decision == "VERIFIED"  # False confidence!

        # Red Mercury Combined: Targeted exploit test fails -> Safely blocks patch as FAILED
        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([], {}, [])
        ]
        mock_test.side_effect = [
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_security_regression.py", status="failed", failed_count=1),
        ]
        out_combined = b4_combined.evaluate_patch(sample_benchmark_case, evasive_patch)
        assert out_combined.decision == "FAILED"  # Catches the evasion!


def test_regression_detection_functional_and_security(sample_benchmark_case):
    """Verify detection of both functional regressions and new security defect regressions."""
    b4 = RedMercuryCombinedBaseline()

    # 1. Functional regression (breaks existing unit test)
    func_reg_patch = CandidatePatchDefinition(
        patch_id="TP-FUNC-REG",
        patch_type="regressive_fix",
        ground_truth_label="NON_FIX",
        ground_truth_rationale="Hardcodes return None, breaking valid callers",
        expected_classification="FAILED",
        expected_regression_status="RESOLVED_BY_DEFINED_CHECKS",
        unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -2,2 +2,2 @@\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    return None\n",
        description="Breaks functionality",
    )

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([], {}, [])
        ]
        # Baseline unit test passed, but patched unit test failed
        mock_test.side_effect = [
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_existing.py", status="failed", failed_count=1, error_message="TypeError: expected str"),
            TestExecutionOutcome(test_suite_name="test_security_regression.py", status="passed", passed_count=1),
        ]

        out = b4.evaluate_patch(sample_benchmark_case, func_reg_patch)
        assert out.decision == "FAILED"
        assert out.evidence["test_regression_detected"] is True
        assert "Functional test regression" in out.evidence["rationale"]

    # 2. Security regression (introduces a new security defect)
    sec_reg_patch = CandidatePatchDefinition(
        patch_id="TP-SEC-REG",
        patch_type="security_regression",
        ground_truth_label="NON_FIX",
        ground_truth_rationale="Fixes SQLi but commits hardcoded secret token",
        expected_classification="FAILED",
        expected_regression_status="NEW",
        unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -1,3 +1,5 @@\n+TOKEN = 'ghp_secret1234567890abcdefghijklmnopqrstuvwxyz'\n def auth(u, p):\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    query = 'SELECT * FROM u WHERE n=?'\n",
        description="Introduces secret token",
    )

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        # Baseline: B608 only. Patched: B608 resolved, but B105 (hardcoded secret) newly introduced!
        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([NormalizedFinding(scanner_rule_id="B105", scanner_name="bandit", file_path="src/auth.py", start_line=1)], {}, [])
        ]
        mock_test.side_effect = [
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_security_regression.py", status="passed", passed_count=1),
        ]

        out_sec = b4.evaluate_patch(sample_benchmark_case, sec_reg_patch)
        assert out_sec.decision == "FAILED"
        assert out_sec.evidence["new_findings_count"] >= 1
        assert "new security finding" in out_sec.evidence["rationale"]


def test_scanner_failures_and_timeouts_force_inconclusive(sample_benchmark_case):
    """Verify that tool failures or timeouts enforce epistemic honesty (INCONCLUSIVE)."""
    b4 = RedMercuryCombinedBaseline()
    true_patch = sample_benchmark_case.candidate_patches[0]

    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.verification.runner import TestExecutionOutcome

        # Scanner reports a subprocess timeout or syntax crash error
        mock_scan.side_effect = [
            ([], {}, ["Bandit execution timed out after 20 seconds"]),
            ([], {}, [])
        ]
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_existing.py", status="passed", passed_count=1
        )

        out = b4.evaluate_patch(sample_benchmark_case, true_patch)
        assert out.decision == "INCONCLUSIVE"
        assert "Tool failure or timeout" in out.evidence["rationale"]
        assert out.error_message is not None


def test_misleading_ai_assessment_plausibility_bias(sample_benchmark_case):
    """Verify that simulated AI judge is misled by cosmetic plausibility while Red Mercury rejects it."""
    b3 = AiJudgeBaseline()
    b4 = RedMercuryCombinedBaseline()

    misleading_patch = CandidatePatchDefinition(
        patch_id="TP-AI-MISLEADING",
        patch_type="cosmetic_evasion",
        ground_truth_label="NON_FIX",
        ground_truth_rationale="Plausible-sounding sanitize_input helper that does not fix SQLi sink",
        expected_classification="FAILED",
        expected_regression_status="STILL_PRESENT",
        unified_diff="--- a/src/auth.py\n+++ b/src/auth.py\n@@ -2,2 +2,4 @@\n-    query = f'SELECT * FROM u WHERE n=\"{u}\"'\n+    # Secure sanitizer implementation compliant with OWASP Top 10\n+    clean_u = str(u).strip()\n+    query = f'SELECT * FROM u WHERE n=\"{clean_u}\"'\n",
        description="Superficial docstring and str.strip()",
    )

    # 1. AI Judge looks at diff syntax -> Falsely concludes it is VERIFIED
    ai_out = b3.evaluate_patch(sample_benchmark_case, misleading_patch)
    assert ai_out.decision == "VERIFIED"
    assert "plausibility bias" in ai_out.evidence["rationale"].lower() or "syntactic" in ai_out.evidence["rationale"].lower()

    # 2. Red Mercury Combined executes exploit test -> Catches failure
    with patch("app.verification.runner.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.runner.run_pytest_in_workspace") as mock_test:
        from app.scanner.base import NormalizedFinding
        from app.verification.runner import TestExecutionOutcome

        mock_scan.side_effect = [
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=2)], {}, []),
            ([NormalizedFinding(scanner_rule_id="B608", scanner_name="bandit", file_path="src/auth.py", start_line=4)], {}, [])
        ]
        mock_test.side_effect = [
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_existing.py", status="passed", passed_count=1),
            TestExecutionOutcome(test_suite_name="test_security_regression.py", status="failed", failed_count=1),
        ]

        rs_out = b4.evaluate_patch(sample_benchmark_case, misleading_patch)
        assert rs_out.decision == "FAILED"


def test_wilson_score_confidence_intervals_and_small_sample_bounds():
    """Verify Wilson score interval calculations on small sample sizes and boundary values."""
    from benchmark.metrics import calculate_wilson_score_interval

    # 1. Zero successes out of 5 (0%)
    lower_0, upper_0 = calculate_wilson_score_interval(0, 5)
    assert lower_0 == 0.0
    assert 0.40 <= upper_0 <= 0.45  # Upper bound is non-zero, capturing uncertainty!

    # 2. Perfect score: 5 successes out of 5 (100%)
    lower_100, upper_100 = calculate_wilson_score_interval(5, 5)
    assert 0.55 <= lower_100 <= 0.60  # Lower bound is ~56.6%, revealing that 100% on n=5 has wide uncertainty!
    assert upper_100 == 1.0

    # 3. Intermediate: 10 successes out of 20 (50%)
    lower_50, upper_50 = calculate_wilson_score_interval(10, 20)
    assert 0.29 <= lower_50 <= 0.35
    assert 0.65 <= upper_50 <= 0.71

    # 4. Zero denominator edge case
    assert calculate_wilson_score_interval(0, 0) == (0.0, 0.0)

