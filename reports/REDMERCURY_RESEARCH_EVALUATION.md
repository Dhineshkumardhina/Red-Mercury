# Red Mercury Research Evaluation: Empirical Verification of Security-Fix Evaluation Baselines

**Document Status:** Complete Empirical Research & Methodology Audit  
**Author:** Red Mercury Research Team  
**Date:** October 2026  
**Primary Execution Environment:** Python 3.14.7 | Windows 11 (AMD64/Intel64) | Pytest 9.1.1 | Bandit 1.9.4 | Semgrep 1.180.0  
**Reproducibility Artifacts:** `benchmark/results/latest_evaluation_report.json`, `benchmark/results/realistic/latest_evaluation_report.json`, `benchmark/results/unified/latest_evaluation_report.json`

---

## 1. Executive Summary & Research Objectives

### 1.1 Research Question
Automated code generation tools and automated program repair (APR) systems increasingly propose security patches for identified software vulnerabilities. However, establishing whether a candidate patch genuinely eliminates a vulnerability without introducing regressions is a critical challenge. Single-technique verification methods suffer from well-documented failure modes:
1. **Static Analysis (SAST) Alone:** Prone to false confidence via cosmetic evasions, syntactic restructuring, and rule insensitivity.
2. **Existing Unit Tests Alone:** Incapable of verifying security properties because generic test suites exercise only benign functional behavior (happy paths).
3. **Targeted Dynamic Tests Alone:** Blind to secondary security regressions (such as committed API credentials) and syntax-level regressions outside the test harness.
4. **AI / LLM Judge Alone:** Severely vulnerable to *syntactic plausibility bias*, frequently certifying cosmetic evasions, partial sanitizers, and non-functional patches because the diff *looks* plausible.

This empirical evaluation investigates the central research question:
> **Does combining static analysis delta, targeted dynamic exploit regression tests, baseline vulnerability reproduction, and strict epistemic outcome handling significantly improve the reliability of security-fix verification compared to individual baselines?**

### 1.2 Summary of Findings Across Benchmark Partitions
We evaluate five comparative verification pipelines across three rigorously governed evaluation sets:

| Evaluation Dataset Partition | Cases | Candidate Patches | Ground Truth Breakdown | Primary Research Purpose |
| :--- | :---: | :---: | :---: | :--- |
| **Reproduced Baseline Suite** | 7 | 23 | 5 FIX, 15 NON_FIX, 3 INCONCLUSIVE | Clean reproduction of established results; dev vs. held-out audit |
| **Realistic Open-Source Suite** | 4 | 16 | 4 FIX, 11 NON_FIX, 1 INCONCLUSIVE | Real-world CVE adaptations (Requests, Werkzeug, Starlette, IPython) |
| **Pooled Unified Suite** | 11 | 39 | 9 FIX, 26 NON_FIX, 4 INCONCLUSIVE | Cross-paradigm statistical evaluation and uncertainty estimation |

#### High-Level Empirical Summary Table

| Verification Approach | Baseline Suite Accuracy (n=23) | Realistic Suite Accuracy (n=16) | Unified Suite Accuracy (n=39) | Unified Precision | Unified Recall | Unified Specificity | Unified F1 | Unified FPR | Unified Inconclusive Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 60.9% | 68.8% | 64.1% | 36.4% | 44.4% | 73.3% | 40.0% | 26.7% | 56.4% |
| **Targeted Tests Alone (Exploit Suite)** | 65.2% | 75.0% | 69.2% | 47.4% | 100.0% | 66.7% | 64.3% | 33.3% | 7.7% |
| **Existing Unit Tests Alone (General Suite)** | 47.8% | 50.0% | 48.7% | 33.3% | 100.0% | 33.3% | 50.0% | 66.7% | 0.0% |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 52.2% | 50.0% | 51.3% | 32.1% | 100.0% | 36.7% | 48.6% | 63.3% | 5.1% |
| **Red Mercury Combined Multi-Tier Gate** | **100.0%** | **93.8%** | **97.4%** | **90.0%** | **100.0%** | **96.7%** | **94.7%** | **3.3%** | **10.3%** |

### 1.3 Scientific Disavowal of Universal Accuracy
> [!IMPORTANT]
> **Scientific Integrity Notice:** While the Red Mercury Combined Pipeline achieved 100.0% correctness on the original 23 synthetic benchmark patches, **we explicitly do NOT claim that the combined approach is universally accurate or infallible.**
> 
> As revealed in Section 9 of this report, when evaluated against the newly introduced realistic open-source CVE benchmark, Red Mercury achieved **93.8% correctness (15/16)** and committed one False Positive (`REAL-002-P4`). In that case, an attacker patch fixed a Denial of Service vulnerability (passing targeted tests) but committed a hardcoded administrative token that fell outside the configured scanner's default AST rule profile. 
> 
> Small-sample datasets exhibit substantial statistical uncertainty (e.g., Wilson 95% confidence intervals span $[56.6\%, 100.0\%]$ for $n=5$ true fixes). Any automated verification engine is fundamentally bounded by the coverage, sensitivity, and isolation of its constituent tools.

---

## 2. Dataset Source, Governance & Case Definitions

### 2.1 Dataset Provenance & Curation Protocol
The Red Mercury evaluation corpus consists of two distinct dataset tiers:

1. **Synthetic Curated Benchmark (`RS-BENCH-001` through `RS-BENCH-007`):**  
   Designed to model canonical CWE archetypes with exact structural isolation. Each case contains a vulnerable baseline Python module, pre-existing functional unit tests, an exploit-demonstrating targeted test harness, and multiple candidate patches exhibiting distinct flaw types (clean fixes, cosmetic evasions, incomplete filters, functional regressions, security regressions, false positive refactors, and tool failure timeouts).

2. **Realistic Open-Source CVE Benchmark (`RS-BENCH-REAL-001` through `RS-BENCH-REAL-004`):**  
   Derived from real-world, permissively licensed open-source vulnerabilities:
   - **Requests (CVE-2023-32681, Apache-2.0):** Sensitive `Proxy-Authorization` header exposure across HTTPS redirects to different hosts/schemes.
   - **Werkzeug (CVE-2023-25577, BSD-3-Clause):** Denial of Service and memory exhaustion via unbounded multipart form parts count.
   - **Starlette / FastAPI (CVE-2022-39286, BSD-3-Clause):** Path traversal in static file asset serving on Windows systems via separator inconsistencies.
   - **IPython (CVE-2022-21699, BSD-3-Clause):** Local privilege escalation and arbitrary code execution via untrusted search path loading profiles from the Current Working Directory (CWD).

### 2.2 Case Definition Taxonomy

| Case ID | Provenance | CVE ID | CWE ID | Vulnerability Category | Baseline Rule ID | Split | Patches | Description |
| :--- | :--- | :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| `RS-BENCH-001` | Synthetic | N/A | CWE-89 | `sql_injection` | `B608` | `dev` | 5 | SQL injection via unparameterized f-string in authentication |
| `RS-BENCH-002` | Synthetic | N/A | CWE-78 | `command_injection` | `B602` | `dev` | 4 | Command injection via `shell=True` in tar backup utility |
| `RS-BENCH-003` | Synthetic | N/A | CWE-22 | `path_traversal` | `RS-PATH-TRAVERSAL` | `dev` | 4 | Directory traversal in static asset server via unvalidated paths |
| `RS-BENCH-004` | Synthetic | N/A | CWE-502 | `deserialization` | `B506` | `held_out` | 4 | Insecure YAML deserialization via unsafe `yaml.Loader` |
| `RS-BENCH-005` | Synthetic | N/A | CWE-862 | `broken_access_control` | `RS-AUTHZ-UNOBSERVED` | `held_out` | 2 | Missing tenant isolation check; unobserved by AST scanners |
| `RS-BENCH-006` | Synthetic | N/A | CWE-89 | `false_positive_finding` | `B608` | `held_out` | 2 | False positive finding on whitelist-validated SQL sort direction |
| `RS-BENCH-007` | Synthetic | N/A | CWE-400 | `tool_failure_timeout` | `B999_UNSUPPORTED` | `held_out` | 2 | Tool crashes, malformed patch path traversal, scanner timeouts |
| `RS-BENCH-REAL-001` | Open-Source | CVE-2023-32681 | CWE-200 | `sensitive_data_exposure` | `RS-CRED-LEAK` | `held_out` | 4 | Cross-origin redirect forwards `Proxy-Authorization` headers |
| `RS-BENCH-REAL-002` | Open-Source | CVE-2023-25577 | CWE-400 | `resource_management` | `RS-DOS-UNBOUNDED` | `held_out` | 4 | Unbounded multipart body parsing leading to memory/CPU DoS |
| `RS-BENCH-REAL-003` | Open-Source | CVE-2022-39286 | CWE-22 | `path_traversal` | `RS-PATH-TRAVERSAL` | `held_out` | 4 | Static asset path traversal escaping base directory on Windows |
| `RS-BENCH-REAL-004` | Open-Source | CVE-2022-21699 | CWE-426 | `broken_access_control` | `RS-CWD-SEARCH` | `held_out` | 4 | Untrusted search path profile execution from CWD |

### 2.3 Ground-Truth Label Definitions & Semantics
Every candidate patch is tagged with one of three formal ground-truth labels:
- **`FIX` (Positive Case):** The patch completely and safely eliminates the vulnerability sink/flaw without introducing functional regressions, without introducing secondary security flaws, and preserves expected system behavior.
- **`NON_FIX` (Negative Case):** The patch is defective. This encompasses:
  - *Cosmetic Evasions:* Modifies variable names or indirection to evade AST linters while leaving runtime vulnerability intact.
  - *Incomplete Fixes:* Implements naive sanitizers (e.g. single `.replace("'", "")` or `clean.replace("../", "")`) easily bypassed by nested or alternate payloads.
  - *Functional Regressions:* Disables functionality (e.g. `return None`, raising unhandled exceptions) causing standard unit tests to fail.
  - *Security Regressions:* Eliminates original flaw but introduces a secondary defect (e.g. hardcoded API credentials).
- **`INCONCLUSIVE` (Epistemic Withholding Case):** The test environment lacks sufficient empirical evidence to certify resolution. This occurs when:
  - The baseline vulnerability is unobserved by configured scanners AND no targeted dynamic exploit test exists.
  - The patch diff is structurally malformed or contains malicious path traversal components (`../../../../etc/passwd`).
  - Analysis tools crash, experience unhandled exceptions, or exceed bounded execution timeouts.

---

## 3. Methodological Audit: Dev vs. Held-Out Integrity & Leakage Prevention

### 3.1 Partitioning Protocol (Tasks 3 & 13)
To ensure that benchmark results are not the artifact of hyper-parameter tuning or heuristic over-fitting:
1. **Development Partition (`dev`):** Limited strictly to `RS-BENCH-001`, `RS-BENCH-002`, and `RS-BENCH-003` (13 patches). All initial pipeline logic, diff parsing tolerances, timeout limits, and error classifiers were tuned solely against these three cases.
2. **Held-Out Synthetic Partition (`held_out`):** Consists of `RS-BENCH-004`, `RS-BENCH-005`, `RS-BENCH-006`, and `RS-BENCH-007` (10 patches). These cases were never inspected during verifier parameter selection.
3. **Held-Out Realistic Partition (`held_out_realistic`):** The 4 real-world open-source CVE cases (`RS-BENCH-REAL-001` through `004`, 16 patches) were created after the initial verification system was finalized and evaluated blindly without altering pipeline code to accommodate them.

### 3.2 Automated Deduplication & Collision Audit (Task 4)
We executed the dataset integrity validator (`benchmark/deduplicator.py`) across all 11 cases and 39 candidate patches:

```python
# Deduplication & Leakage Invariants Evaluated:
1. Case ID Uniqueness: seen_case_ids[case.case_id] must have 0 collisions.
2. Patch ID Uniqueness: seen_patch_ids[patch.patch_id] must have 0 collisions across all cases.
3. AST Content Digest Collisions: SHA-256 normalized hash of vulnerable_code across cases.
4. Diff Collisions: SHA-256 normalized hash of candidate unified diffs.
5. Split Leakage: dev_case_hashes.intersection(held_out_case_hashes) == empty_set.
6. Diff Leakage: dev_patch_diffs.intersection(held_out_patch_diffs) == empty_set.
```

**Audit Execution Results:**
- **Total Cases Analyzed:** 11
- **Total Candidate Patches Analyzed:** 39
- **Identifier Collisions Detected:** 0 (Zero duplicate case IDs, zero duplicate patch IDs)
- **Source Code Digest Collisions:** 0 (All 11 baseline source modules are structurally distinct)
- **Unified Diff Collisions:** 0 (All 39 diffs represent unique modifications)
- **Cross-Split Leakage Issues:** 0 (Zero overlap between `dev` and `held_out` partitions)

---

## 4. Empirical Reproduction of Baseline Benchmark (Tasks 5, 6, 7)

### 4.1 Clean Execution Environment & Dependency Manifest
The existing benchmark was reproduced from a clean environment without external network connectivity or persistent state contamination.

```json
{
  "system_environment": {
    "os_family": "Windows (nt)",
    "os_version": "Windows-11-10.0.26300-SP0",
    "architecture": "AMD64 / Intel64 Family 6 Model 151 Stepping 2",
    "python_executable": "C:\\Python314\\python.exe",
    "python_version": "3.14.7"
  },
  "dependency_manifest": {
    "bandit": "1.9.4",
    "pytest": "9.1.1",
    "semgrep": "1.180.0",
    "pydantic": "2.13.5",
    "fastapi": "0.142.2",
    "sqlalchemy": "2.1.3",
    "scikit-learn": "1.9.1",
    "scipy": "1.18.1"
  },
  "execution_command": "python -u scripts/evaluate_fix_verification.py",
  "deterministic_controls": {
    "random_seed": "N/A (deterministic rule-based & subprocess execution)",
    "scanner_timeout_seconds": 20,
    "sandbox_isolation": "ephemeral_tempfile_sandbox",
    "test_isolation": "subprocess_untrusted_ast_inspection"
  }
}
```

### 4.2 Reproduction Verification: Prior vs. Reproduced Metrics
The reproduction run executed all 5 baselines across the 23 baseline candidate patches. Below is the side-by-side comparison between the previously recorded `latest_evaluation_report.json` and our newly reproduced run:

| Baseline Approach | Prior Correctness | Reproduced Correctness | Prior Precision | Repr. Precision | Prior Recall | Repr. Recall | Prior FPR | Repr. FPR | Prior Inconcl. | Repr. Inconcl. | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 60.9% | **60.9%** | 36.4% | **36.4%** | 80.0% | **80.0%** | 38.9% | **38.9%** | 30.4% | **30.4%** | **EXACT MATCH** |
| **Targeted Tests Alone (Exploit Suite)** | 65.2% | **65.2%** | 41.7% | **41.7%** | 100.0% | **100.0%** | 38.9% | **38.9%** | 13.0% | **13.0%** | **EXACT MATCH** |
| **Existing Unit Tests Alone (General Suite)** | 47.8% | **47.8%** | 31.2% | **31.2%** | 100.0% | **100.0%** | 61.1% | **61.1%** | 0.0% | **0.0%** | **EXACT MATCH** |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 52.2% | **52.2%** | 31.2% | **31.2%** | 100.0% | **100.0%** | 61.1% | **61.1%** | 8.7% | **8.7%** | **EXACT MATCH** |
| **Red Mercury Combined Multi-Tier Gate** | 100.0% | **100.0%** | 100.0% | **100.0%** | 100.0% | **100.0%** | 0.0% | **0.0%** | 13.0% | **13.0%** | **EXACT MATCH** |

Every single patch classification reproduced 100% identically. The only variance was minor millisecond-level execution latency differences attributable to CPU scheduling.

---

## 5. Metric Formulations, Denominators & Inconclusive Handling (Tasks 8, 9, 10)

### 5.1 Exact Mathematical Formulations & Denominators

Let $N$ be the total number of evaluated patch instances. Each instance has a ground-truth label $GT \in \{\text{FIX}, \text{NON\_FIX}, \text{INCONCLUSIVE}\}$ and a predicted classification $Pred \in \{\text{VERIFIED}, \text{FAILED}, \text{INCONCLUSIVE}\}$.

#### Safety-Critical Gate Formulations (Default CI/CD Policy)
In security verification, classifying an insecure patch as verified ($\text{Pred}=\text{VERIFIED}$ when $GT \neq \text{FIX}$) is a **catastrophic security hazard**. Conversely, withholding judgment ($\text{Pred}=\text{INCONCLUSIVE}$) on a flawed or unverified patch safely blocks deployment.

- **True Positives (TP):** $GT = \text{FIX} \land Pred = \text{VERIFIED}$
- **False Positives (FP):** $GT \in \{\text{NON\_FIX}, \text{INCONCLUSIVE}\} \land Pred = \text{VERIFIED}$
- **True Negatives (TN):** $GT \in \{\text{NON\_FIX}, \text{INCONCLUSIVE}\} \land Pred \in \{\text{FAILED}, \text{INCONCLUSIVE}\}$
- **False Negatives (FN):** $GT = \text{FIX} \land Pred \in \{\text{FAILED}, \text{INCONCLUSIVE}\}$

From these counts:
$$
\text{Precision} = \frac{TP}{TP + FP} \quad (\text{Denominator: total candidate patches declared VERIFIED})
$$
$$
\text{Recall (Sensitivity)} = \frac{TP}{TP + FN} \quad (\text{Denominator: total ground-truth FIX patches})
$$
$$
\text{Specificity (True Negative Rate)} = \frac{TN}{TN + FP} \quad (\text{Denominator: total non-fix and inconclusive patches})
$$
$$
\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN} = 1 - \text{Specificity}
$$
$$
\text{F1 Score} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}
$$
$$
\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}
$$
$$
\text{Inconclusive Rate} = \frac{\sum [Pred = \text{INCONCLUSIVE}]}{N}
$$
$$
\text{Regression Detection Rate} = \frac{\sum [r \in \text{Regressions} \land Pred = \text{FAILED}]}{\text{Total Regressive Patches}}
$$

### 5.2 Separate Reporting of Case Populations (Task 9)
In accordance with Task 9, we report the distribution of candidate cases across ground-truth classes separately:

| Population Category | Baseline Suite (n=23) | Realistic Suite (n=16) | Unified Suite (n=39) | Definition |
| :--- | :---: | :---: | :---: | :--- |
| **Positive Cases ($GT = \text{FIX}$)** | 5 (21.7%) | 4 (25.0%) | 9 (23.1%) | Genuine security fixes eliminating vulnerability sink without regressions |
| **Negative Cases ($GT = \text{NON\_FIX}$)** | 15 (65.2%) | 11 (68.8%) | 26 (66.7%) | Flawed patches: cosmetic evasions, incomplete sanitizers, regressions |
| **Inconclusive Cases ($GT = \text{INCONCLUSIVE}$)** | 3 (13.0%) | 1 (6.2%) | 4 (10.3%) | Unobserved scanner findings, malformed diffs, missing test harnesses |

### 5.3 Formal Handling of Inconclusive Outcomes (Task 10)
A major methodological weakness in prior APR and security literature is forcing binary classifiers to make decisive guesses when evidence is missing. Red Mercury explicitly models **epistemic uncertainty**:

1. **Safety-Critical Gate Handling (Conservative Block):**  
   If the pipeline outputs `INCONCLUSIVE` (due to missing test harnesses, unobserved scanner rules, or tool timeouts), the gate refuses to certify the patch. In a CI/CD pipeline, an unverified patch cannot be merged. Therefore, on negative examples ($GT=\text{NON\_FIX}$ or $GT=\text{INCONCLUSIVE}$), returning `INCONCLUSIVE` is categorized as a safe block / True Negative ($\text{TN}$), preserving deployment security. On positive examples ($GT=\text{FIX}$), returning `INCONCLUSIVE` is categorized as a False Negative ($\text{FN}$) because a valid fix was withheld.

2. **Decisive-Only Handling (Coverage-Adjusted Metrics):**  
   To evaluate how the system performs when it *does* make a decisive judgment, inconclusive cases are separated out into an **Inconclusive Rate** (Coverage = $1 - \text{Inconclusive Rate}$). On decisive samples only, precision and recall are computed strictly over $\{VERIFIED, FAILED\}$.

3. **3x3 Ternary Contingency Formulation:**  
   To avoid collapsing distinctions, Section 6 reports the complete $3 \times 3$ matrix mapping ground truth $\{FIX, NON\_FIX, INCONCLUSIVE\}$ against predicted $\{VERIFIED, FAILED, INCONCLUSIVE\}$.

---

## 6. Comprehensive Confusion Matrices & Statistical Significance

### 6.1 Reproduced Baseline Suite (n=23 Patches)

#### Summary Metrics Table

| Baseline Approach | Correct Class. Rate | Accuracy | Precision | Recall | Specificity | F1 Score | FPR | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 60.9% | 65.2% | 36.4% | 80.0% | 61.1% | 50.0% | 38.9% | 30.4% | 0.0% | 1791.3ms |
| **Targeted Tests Alone (Exploit Suite)** | 65.2% | 69.6% | 41.7% | 100.0% | 61.1% | 58.8% | 38.9% | 13.0% | 28.6% | 1139.8ms |
| **Existing Unit Tests Alone (General Suite)** | 47.8% | 52.2% | 31.2% | 100.0% | 38.9% | 47.6% | 61.1% | 0.0% | 85.7% | 1109.1ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 52.2% | 52.2% | 31.2% | 100.0% | 38.9% | 47.6% | 61.1% | 8.7% | 71.4% | 250.0ms |
| **Red Mercury Combined Multi-Tier Gate** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **13.0%** | **100.0%** | 5075.2ms |

#### Binary Confusion Matrix Breakdown

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Predictions |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 4 | **7** | 11 | 1 | 7 |
| **Targeted Tests Alone (Exploit Suite)** | 5 | **7** | 11 | 0 | 3 |
| **Existing Unit Tests Alone (General Suite)** | 5 | **11** | 7 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 5 | **11** | 7 | 0 | 2 |
| **Red Mercury Combined Multi-Tier Gate** | **5** | **0** | **18** | **0** | **3** |

*\*Note: Every FP represents a catastrophic failure where an insecure patch was certified as verified.*

#### Granular 3x3 Ternary Outcome Distribution

```
Baseline Approach: Static Analysis Alone (SAST Delta)
               Pred: VERIFIED  Pred: FAILED  Pred: INCONCLUSIVE
GT: FIX              4              0                1
GT: NON_FIX          7              4                4
GT: INCONCLUSIVE     0              1                2

Baseline Approach: Targeted Tests Alone (Exploit Regression Suite)
               Pred: VERIFIED  Pred: FAILED  Pred: INCONCLUSIVE
GT: FIX              5              0                0
GT: NON_FIX          7              8                0
GT: INCONCLUSIVE     0              1                2

Baseline Approach: Existing Unit Tests Alone (General Test Suite)
               Pred: VERIFIED  Pred: FAILED  Pred: INCONCLUSIVE
GT: FIX              5              0                0
GT: NON_FIX         11              4                0
GT: INCONCLUSIVE     1              2                0

Baseline Approach: AI / LLM Judge Alone (Syntactic Heuristic)
               Pred: VERIFIED  Pred: FAILED  Pred: INCONCLUSIVE
GT: FIX              5              0                0
GT: NON_FIX         11              4                0
GT: INCONCLUSIVE     1              0                2

Baseline Approach: Red Mercury Combined Multi-Tier Gate
               Pred: VERIFIED  Pred: FAILED  Pred: INCONCLUSIVE
GT: FIX              5              0                0
GT: NON_FIX          0             15                0
GT: INCONCLUSIVE     0              0                3
```

### 6.2 Statistical Significance (McNemar's Test)
We compute McNemar's chi-squared test with Edwards continuity correction ($\alpha = 0.05$) across paired candidate patch outcomes:

- **Red Mercury vs. Static Analysis Alone (SAST Delta):**  
  Discordant pairs: Red Mercury correct & SAST incorrect = 9; SAST correct & Red Mercury incorrect = 0.  
  $$\chi^2 = \frac{(|9 - 0| - 1)^2}{9} = \frac{64}{9} \approx 7.111, \quad p = 0.0077 \quad \rightarrow \text{\textbf{Statistically Significant (p < 0.01)}}$$

- **Red Mercury vs. Targeted Tests Alone:**  
  Discordant pairs: Red Mercury correct & Targeted incorrect = 8; Targeted correct & Red Mercury incorrect = 0.  
  $$\chi^2 = \frac{(|8 - 0| - 1)^2}{8} = \frac{49}{8} = 6.125, \quad p = 0.0133 \quad \rightarrow \text{\textbf{Statistically Significant (p < 0.05)}}$$

- **Red Mercury vs. Existing Unit Tests Alone:**  
  Discordant pairs: Red Mercury correct & Tests incorrect = 12; Tests correct & Red Mercury incorrect = 0.  
  $$\chi^2 = \frac{(|12 - 0| - 1)^2}{12} = \frac{121}{12} \approx 10.083, \quad p = 0.0015 \quad \rightarrow \text{\textbf{Statistically Significant (p < 0.01)}}$$

- **Red Mercury vs. AI / LLM Judge Alone:**  
  Discordant pairs: Red Mercury correct & AI incorrect = 11; AI correct & Red Mercury incorrect = 0.  
  $$\chi^2 = \frac{(|11 - 0| - 1)^2}{11} = \frac{100}{11} \approx 9.091, \quad p = 0.0026 \quad \rightarrow \text{\textbf{Statistically Significant (p < 0.01)}}$$

---

## 7. Small-Sample Uncertainty & Wilson Score Intervals (Task 14)

### 7.1 Why Small Samples Demand Wilson Score Intervals
In empirical software engineering, researchers often report point estimates such as "100% precision" or "100% recall" on benchmarks containing a modest number of positive cases ($n = 5$ or $n = 9$). Standard normal approximation confidence intervals ($\hat{p} \pm 1.96 \sqrt{\hat{p}(1-\hat{p})/n}$) break down completely at the boundaries: when $\hat{p} = 1.0$, the variance is calculated as $0$, erroneously implying a confidence interval of $[1.0, 1.0]$ with zero uncertainty.

To provide rigorous scientific transparency, we compute **Wilson Score Intervals** (Wilson, 1927) with 95% confidence:
$$
\text{Center} = \frac{\hat{p} + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{Margin} = \frac{z}{1 + \frac{z^2}{n}} \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}
$$
$$
\text{CI}_{95\%} = \left[\max\left(0, \text{Center} - \text{Margin}\right), \; \min\left(1, \text{Center} + \text{Margin}\right)\right]
$$

### 7.2 95% Confidence Intervals Across Baselines

#### Baseline Suite Uncertainty Analysis (n=23)

| Baseline Approach | Precision [95% CI] | Recall [95% CI] | Specificity [95% CI] | Accuracy [95% CI] |
| :--- | :---: | :---: | :---: | :---: |
| **Static Analysis Alone** | 36.4% [15.2%, 64.6%] | 80.0% [37.6%, 96.4%] | 61.1% [38.6%, 79.7%] | 65.2% [44.9%, 81.2%] |
| **Targeted Tests Alone** | 41.7% [19.3%, 68.0%] | 100.0% [56.6%, 100.0%] | 61.1% [38.6%, 79.7%] | 69.6% [49.1%, 84.4%] |
| **Existing Unit Tests** | 31.2% [14.1%, 55.6%] | 100.0% [56.6%, 100.0%] | 38.9% [20.3%, 61.4%] | 52.2% [33.0%, 70.8%] |
| **AI / LLM Judge Alone** | 31.2% [14.1%, 55.6%] | 100.0% [56.6%, 100.0%] | 38.9% [20.3%, 61.4%] | 52.2% [33.0%, 70.8%] |
| **Red Mercury Combined** | **100.0% [56.6%, 100.0%]** | **100.0% [56.6%, 100.0%]** | **100.0% [82.4%, 100.0%]** | **100.0% [85.7%, 100.0%]** |

#### Unified Pooled Suite Uncertainty Analysis (n=39)

| Baseline Approach | Precision [95% CI] | Recall [95% CI] | Specificity [95% CI] | Accuracy [95% CI] |
| :--- | :---: | :---: | :---: | :---: |
| **Static Analysis Alone** | 36.4% [15.2%, 64.6%] | 44.4% [18.9%, 73.3%] | 75.9% [57.9%, 87.8%] | 66.7% [51.0%, 79.4%] |
| **Targeted Tests Alone** | 47.4% [27.3%, 68.3%] | 100.0% [70.1%, 100.0%] | 66.7% [48.8%, 80.8%] | 74.4% [58.9%, 85.4%] |
| **Existing Unit Tests** | 33.3% [18.6%, 52.2%] | 100.0% [70.1%, 100.0%] | 40.0% [24.6%, 57.7%] | 53.8% [38.6%, 68.4%] |
| **AI / LLM Judge Alone** | 32.1% [17.9%, 50.7%] | 100.0% [70.1%, 100.0%] | 36.7% [21.9%, 54.5%] | 51.3% [36.3%, 66.0%] |
| **Red Mercury Combined** | **90.0% [59.6%, 98.2%]** | **100.0% [70.1%, 100.0%]** | **96.7% [83.3%, 99.4%]** | **97.4% [86.8%, 99.5%]** |

### 7.3 Limitations of Small Samples
The Wilson intervals demonstrate that:
1. For $n=5$ positive samples, a point estimate of $100\%$ recall has a lower bound of **$56.6\%$**. Even at $n=9$ positive samples, the lower bound is **$70.1\%$**.
2. Claims that an APR or verification pipeline achieves "perfect zero-defect verification" based on small benchmarks are statistically unsound.
3. Increasing sample size from 23 to 39 narrows the accuracy interval from $[85.7\%, 100.0\%]$ to $[86.8\%, 99.5\%]$, providing substantially higher statistical power while exposing real-world edge cases.

---

## 8. Evaluation Hardening & Edge-Case Failure Mode Test Suite (Task 11)

To ensure that the verification engine is resilient against known adversarial techniques and tool limitations, we expanded the test suite (`tests/test_benchmark_framework.py`) with 6 dedicated test scenarios (totaling 18 automated tests):

### 8.1 Incomplete Fixes & Partial Sanitizer Bypasses (`test_incomplete_fix_rejected_by_targeted_regression_test`)
- **Vulnerability Scenario:** SQL injection in user authentication.
- **Candidate Patch:** Applies a naive sanitization call: `u_clean = u.replace("'", "")`.
- **Failure Mode:** Suppresses simple AST string concatenations, evading naive pattern matches.
- **Verification Mechanism:** The targeted exploit harness executes an alternate payload (`" OR "1"="1`). The test fails, and Red Mercury successfully rejects the patch (`decision = FAILED`).

### 8.2 False Confidence in Single Baselines (`test_false_confidence_in_sast_alone_and_unit_tests`)
- **Vulnerability Scenario:** Cosmetic evasion rewriting variable structures across multiple lines.
- **Failure Mode:** 
  - SAST alone reports 0 findings because the specific AST rule (`B608`) expects a single expression. Result: **False Positive (VERIFIED)**.
  - Existing unit tests pass because the happy path does not contain malicious syntax. Result: **False Positive (VERIFIED)**.
- **Verification Mechanism:** Red Mercury executes the targeted security regression harness, detects runtime exploitation, and correctly flags the patch as `FAILED`.

### 8.3 Functional & Security Regressions (`test_regression_detection_functional_and_security`)
- **Scenario A (Functional Regression):** A patch that fixes SQL injection by returning `None` or raising an unhandled exception for all callers. Red Mercury's differential unit test runner catches that the test passed in baseline but failed in patched code (`test_regression_detected = True`), blocking the patch.
- **Scenario B (Security Regression):** A patch that parameterizes SQL queries correctly but commits a hardcoded secret token (`TOKEN = 'ghp_secret...'`). Red Mercury's differential finding comparator detects a `NEW` high-severity finding in the modified file, blocking the patch.

### 8.4 Scanner Failures, Timeouts & Unobserved Rules (`test_scanner_failures_and_timeouts_force_inconclusive`)
- **Scenario:** Bandit scanner times out after 20 seconds, crashes due to syntax errors, or encounters an unsupported rule ID (`B999_UNSUPPORTED`).
- **Failure Mode:** In naive CI systems, a scanner crash or timeout is often ignored (exit code 0 or swallowed exception), leading to accidental deployment.
- **Verification Mechanism:** Red Mercury enforces epistemic honesty: any unhandled scanner error or timeout halts verification and returns `INCONCLUSIVE` with explicit error logging, refusing to declare the fix verified.

### 8.5 Misleading AI Assessments & Syntactic Plausibility Bias (`test_misleading_ai_assessment_plausibility_bias`)
- **Scenario:** A patch wraps an unescaped query parameter with `clean_u = str(u).strip()` and adds an elaborate docstring: `# Secure sanitizer implementation compliant with OWASP Top 10`.
- **Failure Mode:** Zero-shot LLM judges evaluate the diff syntactically, observe the function name and docstring, and falsely conclude that the vulnerability was resolved (**False Positive**).
- **Verification Mechanism:** Red Mercury grounds judgment in dynamic execution. The exploit test executes, fails, and the patch is safely rejected.

### 8.6 Mathematical Bounds & Small-Sample Uncertainty (`test_wilson_score_confidence_intervals_and_small_sample_bounds`)
- Tests mathematical edge cases of `calculate_wilson_score_interval`:
  - $k=0, n=5 \rightarrow [0.0, 0.4345]$ (non-zero upper bound capturing uncertainty).
  - $k=5, n=5 \rightarrow [0.5655, 1.0]$ (demonstrating wide lower bound on small positive sets).
  - $n=0 \rightarrow (0.0, 0.0)$ (safe handling of zero denominators).

---

## 9. Expanded Realistic Open-Source Benchmark Evaluation (Tasks 12, 13, 14)

### 9.1 Open-Source CVE Case Descriptions
We created four self-contained, reproducible testbeds adapted from real open-source Python CVEs in `benchmark/cases_realistic/`:

1. **`RS-BENCH-REAL-001` (Requests CVE-2023-32681, CWE-200):**  
   In `requests < 2.31.0`, when following an HTTPS redirect to a different host, the `Proxy-Authorization` header was preserved and leaked to untrusted destinations.
   - *P1 (True Fix):* Strips both `Authorization` and `Proxy-Authorization` on cross-origin redirects while preserving them on same-origin redirects.
   - *P2 (Incomplete Fix):* Only strips `Proxy-Authorization` if destination scheme is `http://`, leaving `https://` redirects vulnerable.
   - *P3 (Regressive Fix):* Clears all headers indiscriminately on any redirect, breaking normal custom headers.
   - *P4 (Cosmetic Evasion):* Refactors variable names with a `# Patched CVE-2023-32681` comment without removing the header.

2. **`RS-BENCH-REAL-002` (Werkzeug CVE-2023-25577, CWE-400):**  
   Werkzeug's multipart parser accepted an unbounded number of parts, enabling Denial of Service via CPU/memory exhaustion.
   - *P1 (True Fix):* Binds total parts to 1000 and raises `ValueError` if exceeded.
   - *P2 (Incomplete Fix):* Limits individual part string size to 10,000 bytes, but leaves total parts count unbounded (allowing 100,000 small parts).
   - *P3 (Regressive Fix):* Restricts parts count to 1, causing standard multi-field form uploads to fail.
   - *P4 (Security Regression):* Implements part bounding correctly, but introduces a hardcoded secret token (`DEBUG_ADMIN_KEY`).

3. **`RS-BENCH-REAL-003` (Starlette / FastAPI CVE-2022-39286, CWE-22):**  
   Directory traversal in static file asset serving on Windows systems due to improper canonicalization of drive letters and path separators.
   - *P1 (True Fix):* Resolves canonical absolute paths using `Path.resolve()`, verifies `commonpath`, and raises `PermissionError` if outside static root.
   - *P2 (Incomplete Fix):* Naively strips `../` once, bypassed by `....//`.
   - *P3 (Regressive Fix):* Rejects any path containing `/` or `\\`, breaking nested static assets like `css/app.css`.
   - *P4 (Cosmetic / AI-Misleading Fix):* Adds `sanitize_security_token_path` wrapper with plausible OWASP docstring, but returns raw path.

4. **`RS-BENCH-REAL-004` (IPython CVE-2022-21699, CWE-426):**  
   IPython searched the Current Working Directory (CWD) for configuration profiles, enabling arbitrary code execution if an attacker placed a `.profile_default` in a shared folder.
   - *P1 (True Fix):* Removes CWD search entirely, resolving strictly relative to trusted home directory.
   - *P2 (Incomplete Fix):* Validates profile name characters but retains vulnerable CWD lookup.
   - *P3 (Regressive Fix):* Raises `PermissionError` for all profile lookups, breaking legitimate profile loading.
   - *P4 (Missing Evidence / Epistemic Case):* Scanner rule unobserved and malformed patch forces inconclusive verdict.

### 9.2 Realistic Benchmark Empirical Results (n=16 Patches)

```
=============================================================================================================================
REALISTIC OPEN-SOURCE BENCHMARK RESULTS TABLE (n=16 Candidate Patches across 4 Real-World CVEs)
=============================================================================================================================
| Baseline Approach | Correct Class. Rate | Accuracy | Precision | Recall | Specificity | F1 Score | False Pos. Rate | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 68.8% | 68.8% | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% | 93.8% | 0.0% | 2339.8ms |
| **Targeted Tests Alone (Exploit Suite)** | 75.0% | 81.2% | 57.1% | 100.0% | 75.0% | 72.7% | 25.0% | 0.0% | 40.0% | 1410.2ms |
| **Existing Unit Tests Alone (General Suite)** | 50.0% | 56.2% | 36.4% | 100.0% | 41.7% | 53.3% | 58.3% | 0.0% | 80.0% | 1323.7ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 50.0% | 50.0% | 33.3% | 100.0% | 33.3% | 50.0% | 66.7% | 0.0% | 80.0% | 250.0ms |
| **Red Mercury Combined Multi-Tier Gate** | **93.8%** | **93.8%** | **80.0%** | **100.0%** | **91.7%** | **88.9%** | **8.3%** | **6.2%** | **80.0%** | 6203.6ms |
=============================================================================================================================
```

#### Realistic Confusion Matrix Breakdown

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 0 | **0** | 11 | 4 | 15 |
| **Targeted Tests Alone (Exploit Suite)** | 4 | **3** | 9 | 0 | 0 |
| **Existing Unit Tests Alone (General Suite)** | 4 | **7** | 5 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 4 | **8** | 4 | 0 | 0 |
| **Red Mercury Combined Multi-Tier Gate** | **4** | **1** | **11** | **0** | **1** |

### 9.3 In-Depth Analysis of the Discovered Failure Mode (`REAL-002-P4`)
In patch `REAL-002-P4`, an attacker proposed a fix for Werkzeug CVE-2023-25577 that successfully bounded multipart parts to 1000, eliminating the DoS vulnerability. However, the patch also committed a hardcoded administrative secret token:
```python
# SECURITY REGRESSION: Hardcoded administrative token
DEBUG_ADMIN_KEY = "ghp_abcdefghijklmnopqrstuvwxyz123456"
```
**Why did Red Mercury Combined commit a False Positive (`Pred = VERIFIED`) on this patch?**
1. The targeted exploit regression test passed because the multipart DoS was resolved.
2. The existing functional unit tests passed because form parsing was not regressed.
3. The differential scanner executed Bandit with the default rule profile (`bandit_default`). Bandit's default AST ruleset flags `B105` (hardcoded password strings), but only when variable names contain substrings like `password`, `pass`, `token`, or `secret`. The variable name `DEBUG_ADMIN_KEY` was not matched by Bandit's default heuristics!
4. Consequently, no new scanner finding was reported, and Red Mercury certified the patch as verified.

**Scientific Implications:**
This empirical finding proves that **no verification gate can exceed the detection capabilities of its constituent analyzers**. If a security regression falls outside the scanner's rule profile (e.g., detecting arbitrary high-entropy credentials requires a dedicated scanner adapter like Trufflehog or Gitleaks), the combined pipeline will be blind to it. We document this failure mode as a direct limitation and future work avenue.

---

## 10. Pooled Unified Benchmark Analysis (11 Cases, 39 Patches)

When aggregating both benchmark sets into a single unified evaluation suite (11 cases, 39 candidate patches: 9 True Fixes, 26 Flawed Patches, 4 Inconclusive Cases):

### 10.1 Unified Empirical Metrics Table

| Baseline Approach | Correct Class. Rate | Accuracy | Precision | Recall | Specificity | F1 Score | False Pos. Rate | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 64.1% | 66.7% | 36.4% | 44.4% | 73.3% | 40.0% | 26.7% | 56.4% | 0.0% | 1970.5ms |
| **Targeted Tests Alone (Exploit Suite)** | 69.2% | 74.4% | 47.4% | 100.0% | 66.7% | 64.3% | 33.3% | 7.7% | 33.3% | 1273.6ms |
| **Existing Unit Tests Alone (General Suite)** | 48.7% | 53.8% | 33.3% | 100.0% | 40.0% | 50.0% | 60.0% | 0.0% | 83.3% | 1255.8ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 51.3% | 51.3% | 32.1% | 100.0% | 36.7% | 48.6% | 63.3% | 5.1% | 75.0% | 250.0ms |
| **Red Mercury Combined Multi-Tier Gate** | **97.4%** | **97.4%** | **90.0%** | **100.0%** | **96.7%** | **94.7%** | **3.3%** | **10.3%** | **91.7%** | 5668.7ms |

### 10.2 Unified Confusion Matrix Breakdown

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 4 | **7** | 22 | 5 | 22 |
| **Targeted Tests Alone (Exploit Suite)** | 9 | **10** | 20 | 0 | 3 |
| **Existing Unit Tests Alone (General Suite)** | 9 | **18** | 12 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 9 | **19** | 11 | 0 | 2 |
| **Red Mercury Combined Multi-Tier Gate** | **9** | **1** | **29** | **0** | **4** |

### 10.3 Statistical Significance Across the Unified Benchmark (McNemar's Test)
On the pooled 39-patch dataset, paired McNemar's tests ($\alpha = 0.05$) demonstrate overwhelming statistical significance:

- **Red Mercury vs. SAST Alone:** $\chi^2 = 11.267, \; p = 0.0008 \rightarrow \text{\textbf{Highly Statistically Significant (p < 0.001)}}$
- **Red Mercury vs. Targeted Tests Alone:** $\chi^2 = 7.111, \; p = 0.0077 \rightarrow \text{\textbf{Statistically Significant (p < 0.01)}}$
- **Red Mercury vs. Existing Unit Tests:** $\chi^2 = 17.053, \; p < 0.0001 \rightarrow \text{\textbf{Extremely Statistically Significant (p < 0.0001)}}$
- **Red Mercury vs. AI / LLM Judge Alone:** $\chi^2 = 16.056, \; p < 0.0001 \rightarrow \text{\textbf{Extremely Statistically Significant (p < 0.0001)}}$

---

## 11. Step-by-Step Reproducibility Guide (Task 15)

To independently execute and verify all empirical benchmark suites from a clean checkout, run the following commands:

### Step 1: Environment Verification
```powershell
# Verify Python version and required dependencies
python --version
# Expected: Python 3.10+ (Tested on Python 3.14.7)

python -c "import bandit, pytest, pydantic, sklearn; print('All core benchmark dependencies available.')"
```

### Step 2: Run Benchmark Framework Unit Tests
```powershell
# Executes the 18 automated test cases covering incomplete fixes, regressions, scanner failures, and CIs
python -m pytest tests/test_benchmark_framework.py -v
```

### Step 3: Reproduce the Baseline Benchmark Suite (7 Cases, 23 Patches)
```powershell
# Reproduces existing baseline evaluation and exports to benchmark/results/
python -u scripts/evaluate_fix_verification.py
```
*Outputs generated:*
- `benchmark/results/latest_evaluation_report.json`
- `benchmark/results/benchmark_metrics_summary.csv`
- `benchmark/results/benchmark_samples.csv`
- `benchmark/results/benchmark_evaluation_report.md`

### Step 4: Execute the Realistic Open-Source CVE Suite (4 Cases, 16 Patches)
```powershell
# Executes the 4 real-world CVE benchmark cases and exports to benchmark/results/realistic/
python -u scripts/evaluate_realistic_benchmark.py
```
*Outputs generated:*
- `benchmark/results/realistic/latest_evaluation_report.json`
- `benchmark/results/realistic/benchmark_metrics_summary.csv`
- `benchmark/results/realistic/benchmark_samples.csv`
- `benchmark/results/realistic/benchmark_evaluation_report.md`

### Step 5: Execute the Unified Pooled Benchmark Suite (11 Cases, 39 Patches)
```powershell
# Executes pooled evaluation over all 39 patches and exports to benchmark/results/unified/
python -u scripts/evaluate_unified_benchmark.py
```
*Outputs generated:*
- `benchmark/results/unified/latest_evaluation_report.json`
- `benchmark/results/unified/benchmark_metrics_summary.csv`
- `benchmark/results/unified/benchmark_samples.csv`
- `benchmark/results/unified/benchmark_evaluation_report.md`

---

## 12. Conclusion & Recommendations

1. **Multi-tier evidence grounding is essential for security patch verification.** Single-technique baselines fail catastrophically in deployment:
   - AI judges and general unit tests exhibit false-positive rates exceeding **60%**, certifying cosmetic evasions and broken sanitizers.
   - Static analysis alone fails to detect runtime exploitability, resulting in a **26.7% FPR** and **56.4% inconclusive rate**.
   - Combining differential SAST, unit test regressions, and targeted exploit reproduction lowers the False Positive Rate to **3.3%** and increases F1 score to **94.7%**.

2. **Epistemic honesty prevents false confidence.** Treating inconclusive outcomes (tool failures, unobserved rules, malformed diffs) as unverified rather than guessing prevents insecure code from being deployed into production repositories.

3. **Universal accuracy must not be claimed on small sample sets.** Wilson score confidence intervals mathematically demonstrate that even a 100% score on a small benchmark has an uncertainty interval spanning down to 56.6%. Real-world evaluations against open-source CVEs prove that automated pipelines remain vulnerable to secondary regressions outside their scanner rule profiles. Future extensions should integrate dedicated secret-detection engines (e.g. Trufflehog) and cross-file dataflow analysis to further reduce the residual 3.3% false-positive risk.
