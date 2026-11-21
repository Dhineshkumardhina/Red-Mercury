# Empirical Evaluation of Evidence-Based Security-Fix Verification

**Evaluation Timestamp:** 2026-10-19T16:18:34.902396+00:00  
**Platform:** nt (Windows-11-10.0.26300-SP0) | **Python:** 3.14.7  
**Total Benchmark Cases:** 11 | **Total Evaluated Patches:** 39 (13 dev, 26 held-out)  

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
| **Static Analysis Alone (SAST Delta)** | 64.1% | 69.2% | 36.4% | 44.4% | 76.7% | 40.0% | 23.3% | 56.4% | 0.0% | 1722.1ms |
| **Targeted Tests Alone (Exploit Regression Suite)** | 69.2% | 74.4% | 47.4% | 100.0% | 66.7% | 64.3% | 33.3% | 7.7% | 33.3% | 1097.4ms |
| **Existing Unit Tests Alone (General Test Suite)** | 48.7% | 53.8% | 33.3% | 100.0% | 40.0% | 50.0% | 60.0% | 0.0% | 83.3% | 1077.9ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 51.3% | 51.3% | 32.1% | 100.0% | 36.7% | 48.6% | 63.3% | 5.1% | 75.0% | 250.0ms |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 97.4% | 97.4% | 90.0% | 100.0% | 96.7% | 94.7% | 3.3% | 10.3% | 91.7% | 4883.9ms |

---

## 3. Confusion Matrix Breakdown

### 3.1 Binary Safety-Critical Gate Matrix

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 4 | **7** | 23 | 5 | 22 |
| **Targeted Tests Alone (Exploit Regression Suite)** | 9 | **10** | 20 | 0 | 3 |
| **Existing Unit Tests Alone (General Test Suite)** | 9 | **18** | 12 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 9 | **19** | 11 | 0 | 2 |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 9 | **1** | 29 | 0 | 4 |

*\*Note: In security-fix evaluation, a False Positive (certifying an insecure patch as verified) is a catastrophic security failure.*

### 3.2 Granular 3x3 Ternary Outcome Distribution

| Baseline Approach | Ground Truth Label | Pred: VERIFIED | Pred: FAILED | Pred: INCONCLUSIVE |
| :--- | :--- | :---: | :---: | :---: |
| Static Analysis Alone (SAST Delt | **FIX** | 4 | 0 | 5 |
| Static Analysis Alone (SAST Delt | **NON_FIX** | 7 | 4 | 15 |
| Static Analysis Alone (SAST Delt | **INCONCLUSIVE** | 0 | 2 | 2 |
| Targeted Tests Alone (Exploit Re | **FIX** | 9 | 0 | 0 |
| Targeted Tests Alone (Exploit Re | **NON_FIX** | 10 | 15 | 1 |
| Targeted Tests Alone (Exploit Re | **INCONCLUSIVE** | 0 | 2 | 2 |
| Existing Unit Tests Alone (Gener | **FIX** | 9 | 0 | 0 |
| Existing Unit Tests Alone (Gener | **NON_FIX** | 16 | 10 | 0 |
| Existing Unit Tests Alone (Gener | **INCONCLUSIVE** | 2 | 2 | 0 |
| AI / LLM Judge Alone (Syntactic  | **FIX** | 9 | 0 | 0 |
| AI / LLM Judge Alone (Syntactic  | **NON_FIX** | 17 | 9 | 0 |
| AI / LLM Judge Alone (Syntactic  | **INCONCLUSIVE** | 2 | 0 | 2 |
| Red Mercury Combined Pipeline (Mu | **FIX** | 9 | 0 | 0 |
| Red Mercury Combined Pipeline (Mu | **NON_FIX** | 1 | 25 | 0 |
| Red Mercury Combined Pipeline (Mu | **INCONCLUSIVE** | 0 | 0 | 4 |

---

## 4. Small-Sample Uncertainty & 95% Wilson Score Intervals

| Baseline Approach | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) |
| :--- | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 36.4% [15.2%, 64.6%] | 44.4% [18.9%, 73.3%] | 76.7% [59.1%, 88.2%] | 69.2% [53.6%, 81.4%] |
| **Targeted Tests Alone (Exploit Regression Suite)** | 47.4% [27.3%, 68.3%] | 100.0% [70.1%, 100.0%] | 66.7% [48.8%, 80.8%] | 74.4% [58.9%, 85.4%] |
| **Existing Unit Tests Alone (General Test Suite)** | 33.3% [18.6%, 52.2%] | 100.0% [70.1%, 100.0%] | 40.0% [24.6%, 57.7%] | 53.8% [38.6%, 68.4%] |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 32.1% [17.9%, 50.7%] | 100.0% [70.1%, 100.0%] | 36.7% [21.9%, 54.5%] | 51.3% [36.2%, 66.1%] |
| **Red Mercury Combined Pipeline (Multi-Tier Evidence Gate)** | 90.0% [59.6%, 98.2%] | 100.0% [70.1%, 100.0%] | 96.7% [83.3%, 99.4%] | 97.4% [86.8%, 99.6%] |

---

## 4. Statistical Significance Testing (McNemar's Test)

We evaluate paired 2x2 contingency tables using McNemar's test with Edwards continuity correction ($lpha = 0.05$):

- **Red Mercury vs Baseline A: Static Analysis Alone:** $\chi^2 = 9.600$, $p = 0.0019$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **Red Mercury vs Baseline B: Targeted Tests Alone:** $\chi^2 = 9.091$, $p = 0.0026$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **Red Mercury vs Baseline B2: General Unit Tests Alone:** $\chi^2 = 17.053$, $p = 0.0000$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **Red Mercury vs Baseline C: AI / LLM Judge Alone:** $\chi^2 = 16.056$, $p = 0.0001$ $\rightarrow$ **Statistically Significant (p < 0.05)**

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
