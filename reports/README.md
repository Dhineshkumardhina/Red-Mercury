# 🛡️ Red Mercury — Security Audits & Technical Reports

This directory houses the comprehensive security audit reports, performance evaluations, research benchmarks, and production-readiness verification documentation for Red Mercury.

---

## 📑 Report Directory

| Report | Category | Description |
| :--- | :--- | :--- |
| [REDMERCURY_FINAL_READINESS_REPORT.md](./REDMERCURY_FINAL_READINESS_REPORT.md) | **Production Release** | Comprehensive final system verification and production readiness sign-off. |
| [REDMERCURY_HEALTH_CHECK.md](./REDMERCURY_HEALTH_CHECK.md) | **Architecture & Health** | End-to-end system health, container integrity, and API endpoint verification. |
| [REDMERCURY_AUTH_SECURITY.md](./REDMERCURY_AUTH_SECURITY.md) | **Authentication** | Cryptographic review of JWT rotation, session protection, CSRF defense, and rate-limiting. |
| [REDMERCURY_SEVEN_LAYER_AUDIT.md](./REDMERCURY_SEVEN_LAYER_AUDIT.md) | **Security Architecture** | Complete audit of the 7-layer defense-in-depth architecture. |
| [REDMERCURY_TEST_GAP_AUDIT.md](./REDMERCURY_TEST_GAP_AUDIT.md) | **Test Coverage** | Gap analysis covering unit tests, integration paths, and negative test boundaries. |
| [REDMERCURY_SANDBOX_SECURITY.md](./REDMERCURY_SANDBOX_SECURITY.md) | **Sandbox Isolation** | Container containment, non-root execution, seccomp profiling, and network isolation. |
| [REDMERCURY_RESEARCH_EVALUATION.md](./REDMERCURY_RESEARCH_EVALUATION.md) | **Benchmark & Research** | Empirical evaluation of evidence-based security-fix verification and statistical tests. |
| [REDMERCURY_CI_GATE_FIXES.md](./REDMERCURY_CI_GATE_FIXES.md) | **CI/CD Security Gate** | Hardening and regression verification for the pull-request security gate. |

### Phase-by-Phase Remediation Reports

| Phase Report | Focus Area | Key Outcomes |
| :--- | :--- | :--- |
| [REDMERCURY_PHASE0_SECURITY_TEST_REPORT.md](./REDMERCURY_PHASE0_SECURITY_TEST_REPORT.md) | Initial Gap Discovery | Baseline security assessment and adversarial vulnerability enumeration. |
| [REDMERCURY_PHASE1_REMEDIATION_REPORT.md](./REDMERCURY_PHASE1_REMEDIATION_REPORT.md) | Core Remediation | Resolution of input sanitization, CSRF tokens, and credentials stripping. |
| [REDMERCURY_PHASE2_IMPLEMENTATION_REPORT.md](./REDMERCURY_PHASE2_IMPLEMENTATION_REPORT.md) | Verification Engine | Implementation of multi-tier verification runner and ephemeral sandboxing. |
| [REDMERCURY_PHASE3A_DOCKER_SECURITY_REPORT.md](./REDMERCURY_PHASE3A_DOCKER_SECURITY_REPORT.md) | Container Security | Docker rootless bounding, memory limits, and process-tree termination. |
| [REDMERCURY_PHASE3B_PERFORMANCE_REPORT.md](./REDMERCURY_PHASE3B_PERFORMANCE_REPORT.md) | Scanner Performance | Scanner execution times, AST analysis throughput, and resource profiling. |
| [REDMERCURY_PHASE3C_API_RELIABILITY_REPORT.md](./REDMERCURY_PHASE3C_API_RELIABILITY_REPORT.md) | API Reliability | HTTP concurrency, database connection pooling, and fault tolerance. |
| [REDMERCURY_PHASE3D_E2E_REPORT.md](./REDMERCURY_PHASE3D_E2E_REPORT.md) | E2E User Journeys | Full end-to-end verification workflows from code ingestion to patch verification. |
| [REDMERCURY_PHASE3E_CICD_SECURITY_REPORT.md](./REDMERCURY_PHASE3E_CICD_SECURITY_REPORT.md) | CI/CD Integration | GitHub Actions integration, PR automated comments, and gate enforcement. |
| [REDMERCURY_PHASE3F_PRODUCTION_READINESS_REPORT.md](./REDMERCURY_PHASE3F_PRODUCTION_READINESS_REPORT.md) | Final Readiness | Production configurations, SSL termination, and least-privilege review. |
