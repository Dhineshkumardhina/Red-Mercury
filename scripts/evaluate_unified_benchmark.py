#!/usr/bin/env python3
"""Unified Benchmark Evaluation Runner for Red Mercury.

Runs the complete pooled benchmark across both the original curated cases
and the realistic open-source CVE cases (11 cases, 39 candidate patches).
"""
from pathlib import Path
import shutil
import sys
import tempfile

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from benchmark.runner import run_benchmark_suite
from benchmark.runner import load_benchmark_cases


if __name__ == "__main__":
    cases_orig_dir = WORKSPACE_ROOT / "benchmark" / "cases"
    cases_real_dir = WORKSPACE_ROOT / "benchmark" / "cases_realistic"
    results_dir = WORKSPACE_ROOT / "benchmark" / "results" / "unified"

    # Create temporary merged cases directory
    tmp_cases_dir = Path(tempfile.mkdtemp(prefix="rs_unified_cases_"))
    try:
        for f in cases_orig_dir.glob("*.json"):
            shutil.copy(f, tmp_cases_dir / f.name)
        for f in cases_real_dir.glob("*.json"):
            shutil.copy(f, tmp_cases_dir / f.name)

        print("[*] Starting Red Mercury Unified Fix-Verification Benchmark...")
        summary = run_benchmark_suite(
            cases_dir=tmp_cases_dir,
            results_dir=results_dir,
            split_filter=None,
            timeout_seconds=20,
            verbose=True,
        )
        print(f"[*] Completed unified benchmark: {summary.total_patches} patches across {summary.total_cases} cases.")
    finally:
        shutil.rmtree(tmp_cases_dir, ignore_errors=True)
