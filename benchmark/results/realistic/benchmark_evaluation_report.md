# Empirical Evaluation of Evidence-Based Security-Fix Verification

**Evaluation Timestamp:** 2026-10-19T16:12:18.673536+00:00  
**Platform:** nt (Windows-11-10.0.26300-SP0) | **Python:** 3.14.7  
**Total Benchmark Cases:** 4 | **Total Evaluated Patches:** 16 (0 dev, 16 held-out)  

---

## 1. Research Objective & Baselines

This benchmark investigates the central research question:
> *Does combining static analysis, targeted security tests, and explicit evidence rules improve the reliability of security-fix evaluation compared with single-technique baselines?*

Five comparative evaluation pipelines were executed over identical candidate patches and source code trees:
1. **Baseline A: Static Analysis Alone (SAST Delta):** Certifies a fix if the target scanner rule disappears from the AST.
2. **Baseline B: Targeted Tests Alone (Exploit Regression Suite):** Certifies a fix if the vulnerability exploit fails against patched code.
3. **Baseline B2: General Unit Tests Alone:** Certifies a fix if repository functional unit tests pass in CI.
4. **Baseline C: AI / LLM Judge Alone:** Zero-shot heuristic diff review without execution grounding.
5. **Baseline D: Red Mercury Combined Pipeline:** Multi-tier evidence gate coupling baseline reproduction, differential SAST, unit test regressions, targeted exploit test verification, and 6-status finding classification.

---

## 2. Empirical Benchmark Metrics Summary

| Baseline Approach | Correct Class. Rate | Accuracy | Precision | Recall | Specificity | F1 Score | False Pos. Rate | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 68.8% | 75.0% | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% | 93.8% | 0.0% | 2339.8ms |
| **Targeted Tests Alone (Exploit Regression Suite)** | 75.0% | 81.2% | 57.1% | 100.0% | 75.0% | 72.7% | 25.0% | 0.0% | 40.0% | 1410.2ms |
| **Existing Unit Tests Alone (General Test Suite)** | 50.0% | 56.2% | 36.4% | 100.0% | 41.7% | 53.3% | 58.3% | 0.0% | 80.0% | 1323.7ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 50.0% | 50.0% | 33.3% | 100.0% | 33.3% | 50.0% | 66.7% | 0.0% | 80.0% | 250.0ms |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 93.8% | 93.8% | 80.0% | 100.0% | 91.7% | 88.9% | 8.3% | 6.2% | 80.0% | 6203.6ms |

---

## 3. Confusion Matrix Breakdown

### 3.1 Binary Safety-Critical Gate Matrix

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 0 | **0** | 12 | 4 | 15 |
| **Targeted Tests Alone (Exploit Regression Suite)** | 4 | **3** | 9 | 0 | 0 |
| **Existing Unit Tests Alone (General Test Suite)** | 4 | **7** | 5 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 4 | **8** | 4 | 0 | 0 |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 4 | **1** | 11 | 0 | 1 |

*\*Note: In security-fix evaluation, a False Positive (certifying an insecure patch as verified) is a catastrophic security failure.*

### 3.2 Granular 3x3 Ternary Outcome Distribution

| Baseline Approach | Ground Truth Label | Pred: VERIFIED | Pred: FAILED | Pred: INCONCLUSIVE |
| :--- | :--- | :---: | :---: | :---: |
| Static Analysis Alone (SAST Delt | **FIX** | 0 | 0 | 4 |
| Static Analysis Alone (SAST Delt | **NON_FIX** | 0 | 0 | 11 |
| Static Analysis Alone (SAST Delt | **INCONCLUSIVE** | 0 | 1 | 0 |
| Targeted Tests Alone (Exploit Re | **FIX** | 4 | 0 | 0 |
| Targeted Tests Alone (Exploit Re | **NON_FIX** | 3 | 8 | 0 |
| Targeted Tests Alone (Exploit Re | **INCONCLUSIVE** | 0 | 1 | 0 |
| Existing Unit Tests Alone (Gener | **FIX** | 4 | 0 | 0 |
| Existing Unit Tests Alone (Gener | **NON_FIX** | 7 | 4 | 0 |
| Existing Unit Tests Alone (Gener | **INCONCLUSIVE** | 0 | 1 | 0 |
| AI / LLM Judge Alone (Syntactic  | **FIX** | 4 | 0 | 0 |
| AI / LLM Judge Alone (Syntactic  | **NON_FIX** | 7 | 4 | 0 |
| AI / LLM Judge Alone (Syntactic  | **INCONCLUSIVE** | 1 | 0 | 0 |
| Red Mercury Combined Pipeline (Mu | **FIX** | 4 | 0 | 0 |
| Red Mercury Combined Pipeline (Mu | **NON_FIX** | 1 | 10 | 0 |
| Red Mercury Combined Pipeline (Mu | **INCONCLUSIVE** | 0 | 0 | 1 |

---

## 4. Small-Sample Uncertainty & 95% Wilson Score Intervals

| Baseline Approach | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) |
| :--- | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 0.0% [0.0%, 0.0%] | 0.0% [0.0%, 49.0%] | 100.0% [75.8%, 100.0%] | 75.0% [50.5%, 89.8%] |
| **Targeted Tests Alone (Exploit Regression Suite)** | 57.1% [25.1%, 84.2%] | 100.0% [51.0%, 100.0%] | 75.0% [46.8%, 91.1%] | 81.2% [57.0%, 93.4%] |
| **Existing Unit Tests Alone (General Test Suite)** | 36.4% [15.2%, 64.6%] | 100.0% [51.0%, 100.0%] | 41.7% [19.3%, 68.0%] | 56.2% [33.2%, 76.9%] |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 33.3% [13.8%, 60.9%] | 100.0% [51.0%, 100.0%] | 33.3% [13.8%, 60.9%] | 50.0% [28.0%, 72.0%] |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 80.0% [37.5%, 96.4%] | 100.0% [51.0%, 100.0%] | 91.7% [64.6%, 98.5%] | 93.8% [71.7%, 98.9%] |

---

## 4. Statistical Significance Testing (McNemar's Test)

We evaluate paired 2x2 contingency tables using McNemar's test with Edwards continuity correction ($lpha = 0.05$):

- **Red Mercury vs Baseline A: Static Analysis Alone:** $\chi^2 = 1.500$, $p = 0.2207$ $\rightarrow$ Not statistically significant
- **Red Mercury vs Baseline B: Targeted Tests Alone:** $\chi^2 = 1.333$, $p = 0.2482$ $\rightarrow$ Not statistically significant
- **Red Mercury vs Baseline B2: General Unit Tests Alone:** $\chi^2 = 5.143$, $p = 0.0233$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **Red Mercury vs Baseline C: AI / LLM Judge Alone:** $\chi^2 = 5.143$, $p = 0.0233$ $\rightarrow$ **Statistically Significant (p < 0.05)**

---

## 5. Tool Versions & Reproducibility Environment

```json
{
  "platform": {
    "os": "nt",
    "platform": "Windows-11-10.0.26300-SP0",
    "python_version": "3.14.7",
    "processor": "Intel64 Family 6 Model 151 Stepping 2, GenuineIntel"
  },
  "tool_versions": {
    "python": "3.14.7",
    "bandit": "1.9.4",
    "pytest": "9.1.1"
  },
  "scanner_configuration": {
    "timeout_seconds": 20,
    "rule_profiles": [
      "bandit_default",
      "semgrep_security_audit"
    ],
    "severity_threshold": "LOW",
    "confidence_threshold": "LOW",
    "secret_detector_enabled": true,
    "sandbox_isolation": "disposable_scratchdir"
  }
}
```
