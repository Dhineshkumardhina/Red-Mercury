#!/usr/bin/env python3
"""Evaluation Runner for Realistic Open-Source Security Fix Benchmark (CVE Dataset).

Evaluates the 5 comparative verification baselines across realistic open-source CVE patches:
- CVE-2023-32681 (Requests - Proxy-Authorization header leak)
- CVE-2023-25577 (Werkzeug - Unbounded multipart parts DoS)
- CVE-2022-39286 (Starlette - Static asset path traversal)
- CVE-2022-21699 (IPython - CWD untrusted search path)
"""
from pathlib import Path
import sys

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from benchmark.runner import run_benchmark_suite


if __name__ == "__main__":
    cases_dir = WORKSPACE_ROOT / "benchmark" / "cases_realistic"
    results_dir = WORKSPACE_ROOT / "benchmark" / "results" / "realistic"

    if not cases_dir.exists():
        print(f"[!] Error: Cases dir {cases_dir} not found.", file=sys.stderr)
        sys.exit(1)

    print("[*] Starting Realistic Open-Source Fix Verification Evaluation...")
    summary = run_benchmark_suite(
        cases_dir=cases_dir,
        results_dir=results_dir,
        split_filter=None,
        timeout_seconds=20,
        verbose=True,
    )
    print(f"[*] Completed realistic benchmark: {summary.total_patches} patches across {summary.total_cases} cases.")
