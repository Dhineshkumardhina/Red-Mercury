"""Scan orchestrator and execution engine.

Coordinates execution of real security scanner adapters against repository workspaces,
persists normalized security findings, recalculates repository health score, and
logs audit events with full execution provenance.
"""
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from .base import ScanJobResult, ScannerStatus
from .registry import scanner_registry
from ..core.audit import record_audit_event
from ..core.logging import get_logger
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.scan import Scan

logger = get_logger("redmercury.scanner.runner")


def run_security_scan(
    repo: Repository,
    scan: Scan,
    db: Session,
    selected_tools: Optional[List[str]] = None,
    timeout_per_tool: int = 60,
    options: Optional[Dict[str, Any]] = None,
    commit_changes: bool = True,
    pre_commit_hook: Optional[Any] = None,
) -> Scan:
    """Execute security scanners on repository workspace and update database state.

    Enforces:
    - Safe execution timeouts per scanner.
    - Path isolation within designated repository workspace.
    - Zero execution of untrusted repository scripts.
    - Strict redaction of secrets in findings and metadata.
    - Real metrics update (health score and severity counts).
    """
    logger.info(f"Initiating security scan {scan.id} for repo '{repo.name}' (id={repo.id})")

    # 1. Validate isolated workspace directory
    if not repo.workspace_path:
        error_msg = "Repository workspace path is not set. Ingest source code archive or git repository first."
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        if commit_changes:
            db.commit()
            db.refresh(scan)
        else:
            db.flush()
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    target_path = Path(repo.workspace_path)
    if not target_path.exists() or not target_path.is_dir():
        error_msg = f"Repository workspace path does not exist on disk: {repo.workspace_path}"
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        if commit_changes:
            db.commit()
            db.refresh(scan)
        else:
            db.flush()
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    # 2. Check if already cancelled, else transition scan to running
    if scan.status in ("cancelled", "cancelling"):
        logger.info(f"Scan {scan.id} is already in cancelled status. Aborting scan execution.")
        return scan

    from ..core.jobs import assert_active_worker_lease_or_abort, get_active_tracker
    assert_active_worker_lease_or_abort(db=db, resource_id=str(scan.id))

    if scan.status != "running":
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        if commit_changes:
            db.commit()
        else:
            db.flush()

    # 3. Determine scanner adapters to execute
    adapters_to_run = []
    if selected_tools:
        for tool_name in selected_tools:
            adapter = scanner_registry.get(tool_name)
            if adapter:
                adapters_to_run.append(adapter)
            else:
                logger.warning(f"Requested tool '{tool_name}' not found in registry")
    else:
        # Default: all registered and available adapters
        adapters_to_run = scanner_registry.get_available()

    if not adapters_to_run:
        error_msg = "No available security scanners found to execute in current environment."
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        if commit_changes:
            db.commit()
            db.refresh(scan)
        else:
            db.flush()
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    # 4. Execute each adapter safely
    results = []
    new_findings_count = 0
    scanner_reports = []

    scan_id_val = str(scan.id)
    from ..core.jobs import assert_active_worker_lease_or_abort, get_active_tracker
    active_tracker = get_active_tracker(scan_id_val) or get_active_tracker()

    # Enforce lease fencing BEFORE executing adapters
    assert_active_worker_lease_or_abort(db=db, resource_id=scan_id_val)
    pending_finding_records: List[SecurityFinding] = []
    seen_finding_keys = set()

    def _execute_adapter(adapter):
        from ..core.jobs import register_active_tracker
        if active_tracker is not None:
            register_active_tracker(active_tracker)
            if active_tracker.should_abort():
                return ScanJobResult(
                    scanner_name=adapter.display_name,
                    scanner_version=None,
                    category=adapter.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=0.0,
                    error_message="Scan aborted due to cancellation or lease loss.",
                )
        logger.info(f"Running adapter '{adapter.name}' ({adapter.display_name}) on scan {scan_id_val}")
        try:
            return adapter.scan(
                target_dir=target_path,
                scan_id=scan_id_val,
                timeout_seconds=timeout_per_tool,
                options=options,
            )
        except Exception as exc:
            logger.error(f"Scanner adapter '{adapter.name}' crashed or threw unexpected error: {exc}", exc_info=True)
            version_fn = getattr(adapter, "get_version", None)
            ver = version_fn() if callable(version_fn) else None
            return ScanJobResult(
                scanner_name=adapter.display_name,
                scanner_version=ver,
                category=adapter.category,
                status=ScannerStatus.EXECUTION_ERROR,
                execution_time_seconds=0.0,
                error_message=f"Scanner execution error: {str(exc)}",
            )

    max_workers = min(4, len(adapters_to_run)) if len(adapters_to_run) > 1 else 1
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        ordered_results = list(executor.map(_execute_adapter, adapters_to_run))

    for job_result in ordered_results:
        results.append(job_result)
        total_skipped = getattr(job_result, "skipped_files", []) or []
        scanner_reports.append({
            "scanner_name": job_result.scanner_name,
            "version": job_result.scanner_version,
            "category": job_result.category,
            "status": job_result.status.value,
            "execution_time_seconds": job_result.execution_time_seconds,
            "findings_count": len(job_result.findings),
            "skipped_files_count": len(total_skipped),
            "skipped_files": total_skipped[:25],
            "exit_code": job_result.exit_code,
            "error_message": job_result.error_message,
        })

        # Persist normalized findings with strict deduplication
        for f in job_result.findings:
            dedup_key = (f.file_path, f.start_line, f.scanner_rule_id, f.scanner_name)
            if dedup_key in seen_finding_keys:
                continue
            seen_finding_keys.add(dedup_key)

            title_text = f.scanner_message[:250] if f.scanner_message else f"Security finding {f.scanner_rule_id}"
            finding_record = SecurityFinding(
                repo_id=repo.id,
                scan_id=scan.id,
                scanner_identifier=f.scanner_name,
                scanner_name=f.scanner_name,
                rule_identifier=f.scanner_rule_id,
                cwe=f.cwe or f.vulnerability_category,
                title=title_text,
                category=f.vulnerability_category,
                severity=f.severity,
                confidence=f.confidence,
                confidence_score=0.95 if f.confidence == "HIGH" else 0.75 if f.confidence == "MEDIUM" else 0.50,
                file_path=f.file_path,
                line_number=f.start_line,
                line_information=f"{f.start_line}-{f.end_line}" if f.start_line != f.end_line else str(f.start_line),
                evidence_reference=f.evidence_reference,
                code_excerpt=f.evidence_reference,
                status="open",
                finding_status="open",
            )
            pending_finding_records.append(finding_record)
            new_findings_count += 1

    # 5. Enforce lease fencing BEFORE flushing new findings, repository posture, scan status, or audit events
    assert_active_worker_lease_or_abort(db=db, resource_id=scan_id_val)
    if callable(pre_commit_hook):
        pre_commit_hook()

    # Ensure retries/re-executions do not duplicate findings or corrupt records
    db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan_id_val).delete(synchronize_session=False)
    for finding_record in pending_finding_records:
        db.add(finding_record)
    db.flush()

    from sqlalchemy import func
    counts_by_severity = dict(
        db.query(SecurityFinding.severity, func.count(SecurityFinding.id))
        .filter(
            SecurityFinding.repo_id == repo.id,
            SecurityFinding.status == "open",
        )
        .group_by(SecurityFinding.severity)
        .all()
    )

    crit_count = counts_by_severity.get("CRITICAL", 0)
    high_count = counts_by_severity.get("HIGH", 0)
    med_count = counts_by_severity.get("MEDIUM", 0)
    low_count = counts_by_severity.get("LOW", 0)

    # Calculate enterprise security health score [0, 100]
    health = max(0, 100 - (crit_count * 25 + high_count * 15 + med_count * 5 + low_count * 1))

    repo.critical_count = crit_count
    repo.high_count = high_count
    repo.medium_count = med_count
    repo.low_count = low_count
    repo.health_score = health
    repo.last_scanned_at = datetime.now(timezone.utc)

    # 6. Determine overall scan completion status
    # Strictly preserve cancelled status so cancellation cannot be overwritten
    current_scan = db.query(Scan).filter(Scan.id == scan_id_val).first()
    if not current_scan:
        logger.error(f"Scan {scan_id_val} not found in database during completion step.")
        return scan
    scan = current_scan

    if scan.status == "cancelled":
        logger.info(f"Scan {scan.id} is cancelled. Preserving cancelled status.")
    else:
        any_success = any(r.status in (ScannerStatus.SUCCESS, ScannerStatus.NO_FINDINGS) for r in results)
        any_error = any(r.status in (ScannerStatus.EXECUTION_ERROR, ScannerStatus.TIMEOUT) for r in results)

        if any_error and any_success:
            scan.status = "partial"
        elif any_error and not any_success:
            scan.status = "failed"
        elif any_success:
            scan.status = "completed"
        else:
            scan.status = "failed"

    scan.completed_at = datetime.now(timezone.utc)
    summary_data = {
        "total_findings": new_findings_count,
        "scanners_executed": len(adapters_to_run),
        "scanners": scanner_reports,
        "total_skipped_files": sum(r.get("skipped_files_count", 0) for r in scanner_reports),
        "health_score_after": health,
    }
    scan.summary = json.dumps(summary_data)

    # Record scan completion audit event inside the same lease-fenced transaction
    from ..models.audit import AuditEvent
    from ..core.audit import sanitize_metadata
    clean_meta = sanitize_metadata({
        "repository_id": repo.id,
        "status": scan.status,
        "findings_count": new_findings_count,
        "health_score": health,
    })
    db.add(
        AuditEvent(
            action="SCAN_COMPLETED",
            resource_type="scan",
            resource_identifier=scan.id,
            actor_id=repo.owner_id,
            safe_metadata=json.dumps(clean_meta),
        )
    )
    db.flush()

    if commit_changes:
        try:
            db.commit()
            db.refresh(scan)
        except Exception:
            db.rollback()
            raise

    logger.info(
        f"Completed scan {scan.id} with status={scan.status}, findings={new_findings_count}, health={health}"
    )
    return scan


if __name__ == "__main__":
    from .worker import main
    main()

