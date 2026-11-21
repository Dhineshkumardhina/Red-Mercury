"""Fix Verification Engine API endpoints."""
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, require_mutating_role, verify_finding_ownership, verify_verification_run_ownership
from ....core.errors import ForbiddenError, NotFoundError, SecurityPolicyViolationError, ValidationError
from ....db.session import get_db
from ....models.finding import SecurityFinding
from ....models.repository import Repository
from ....models.user import User
from ....models.verification import VerificationEvidence, VerificationRun
from ....schemas.verification import (
    ClassifiedFinding,
    PatchValidationRequest,
    PatchValidationResult,
    STANDARD_VERIFICATION_LIMITATIONS,
    VerificationEvidenceSchema,
    VerificationRunRequest,
    VerificationRunResponse,
    VerificationStatus,
)
from ....verification.patch_parser import parse_unified_diff
from ....verification.service import execute_fix_verification

router = APIRouter()


@router.post(
    "",
    response_model=VerificationRunResponse,
    summary="Trigger Fix Verification",
    description="Run isolated 5-step fix verification checks on a proposed security patch."
)
def trigger_fix_verification(
    request: VerificationRunRequest,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
):
    """Execute fix verification pipeline against isolated disposable workspace with tenant authorization."""
    # Enforce that the target finding belongs to a repository owned by current_user
    verify_finding_ownership(finding_id=request.finding_id, current_user=current_user, db=db)
    return execute_fix_verification(request, db=db, user_id=current_user.id)


@router.post(
    "/validate-patch",
    response_model=PatchValidationResult,
    summary="Validate Proposed Patch Diff",
    description="Dry-run parsing of a unified diff to verify relative paths, reject traversal, and show file/line deltas."
)
def validate_patch(
    request: PatchValidationRequest,
    current_user: User = Depends(get_current_user),
):
    """Parse diff and ensure changed paths belong safely to repository without path traversal."""
    return parse_unified_diff(request.proposed_patch)


@router.get(
    "",
    response_model=List[VerificationRunResponse],
    summary="List Verification Runs",
    description="List all historical fix verification runs for repositories owned by the current user."
)
def list_verification_runs(
    finding_id: Optional[str] = Query(None, description="Filter runs by finding ID"),
    status: Optional[str] = Query(None, description="Filter runs by verification status"),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Query historical verification runs with decoded metadata, restricted to user-owned repositories."""
    query = (
        db.query(VerificationRun)
        .join(SecurityFinding, VerificationRun.finding_id == SecurityFinding.id)
        .join(Repository, SecurityFinding.repo_id == Repository.id)
        .filter(Repository.owner_id == current_user.id)
    )
    if finding_id:
        verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
        query = query.filter(VerificationRun.finding_id == finding_id)
    if status:
        query = query.filter(VerificationRun.status == status)

    runs = query.order_by(VerificationRun.started_at.desc()).limit(limit).all()

    results: List[VerificationRunResponse] = []
    for r in runs:
        results.append(_format_run_response(r, db))
    return results


@router.get(
    "/{id}",
    response_model=VerificationRunResponse,
    summary="Get Verification Run Details",
    description="Fetch a specific verification run by ID along with its evidence records and limitations."
)
def get_verification_run(
    id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full verification run record, enforcing repository ownership."""
    run = verify_verification_run_ownership(run_id=id, current_user=current_user, db=db)
    return _format_run_response(run, db)


@router.post(
    "/{id}/rerun",
    response_model=VerificationRunResponse,
    summary="Rerun Fix Verification",
    description="Rerun an existing verification run in an isolated disposable workspace."
)
def rerun_verification_run(
    id: str,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
):
    """Rerun fix verification pipeline for an existing run against isolated disposable workspace with tenant authorization."""
    run = verify_verification_run_ownership(run_id=id, current_user=current_user, db=db)

    if not run.patch_diff:
        raise ValidationError("Cannot rerun verification: run does not contain a proposed patch diff.")

    request = VerificationRunRequest(
        finding_id=run.finding_id,
        proposed_patch=run.patch_diff,
        patch_id=run.patch_id,
        run_existing_tests=True,
        run_regression_tests=True,
    )
    return execute_fix_verification(request, db=db, user_id=current_user.id)


@router.post(
    "/{id}/approve-and-merge",
    response_model=Dict[str, Any],
    summary="Approve and Merge Verified Fix",
    description="Enforce authentication, ownership, verified status check, and merge integration capability."
)
def approve_and_merge_verification(
    id: str,
    current_user: User = Depends(require_mutating_role),
    db: Session = Depends(get_db),
):
    """Enforce authentication, repository ownership, verified status check, and merge integration capability."""
    run = verify_verification_run_ownership(run_id=id, current_user=current_user, db=db)

    # 1. Enforce fix verification status: must be VERIFIED_AGAINST_DEFINED_CHECKS
    if run.status != VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS.value and run.status != "VERIFIED_AGAINST_DEFINED_CHECKS":
        raise SecurityPolicyViolationError(
            f"Cannot merge pull request: fix verification status is '{run.status}'. "
            "Only fixes that have successfully passed all verification gates (VERIFIED_AGAINST_DEFINED_CHECKS) can be approved."
        )

    # 2. Enforce merge integration capability:
    # In accordance with Red Mercury's least-privilege security policy, automated direct merging is prohibited / not configured
    record_audit_event(
        db=db,
        action="VERIFICATION_MERGE_ATTEMPTED",
        resource_type="verification_run",
        resource_identifier=id,
        actor_id=current_user.id,
        metadata={"status": run.status, "reason": "Least-privilege policy prohibits direct auto-merge"},
    )
    raise SecurityPolicyViolationError(
        "Automated direct merge is not configured. Red Mercury enforces least-privilege access and does not maintain "
        "write/push credentials to primary branches. Merging must be performed directly in GitHub by an authorized repository maintainer."
    )


def _format_run_response(run: VerificationRun, db: Session) -> VerificationRunResponse:
    """Format a database VerificationRun row into the strict Pydantic response schema."""
    evidence_entities = db.query(VerificationEvidence).filter(
        VerificationEvidence.verification_run_id == run.id
    ).all()

    evidence_schemas = [
        VerificationEvidenceSchema(
            id=ev.id,
            verification_run_id=ev.verification_run_id,
            evidence_type=ev.evidence_type,
            result=ev.result,
            tool_name_and_version=ev.tool_name_and_version,
            evidence_reference=ev.evidence_reference,
            timestamp=ev.timestamp,
        )
        for ev in evidence_entities
    ]

    def safe_json_load(text: Optional[str], default_val):
        if not text:
            return default_val
        try:
            return json.loads(text)
        except Exception:
            return default_val

    # Parse status enum safely
    status_enum = VerificationStatus.NOT_TESTED
    try:
        status_enum = VerificationStatus(run.status)
    except Exception:
        status_enum = VerificationStatus.INCONCLUSIVE

    parsed_test_results = safe_json_load(run.test_results, {})
    raw_classified = safe_json_load(getattr(run, "classified_findings", None), [])
    classified_findings: List[ClassifiedFinding] = []
    for item in raw_classified:
        try:
            classified_findings.append(ClassifiedFinding(**item))
        except Exception:
            pass

    baseline_test_results = parsed_test_results.get("_baseline_test_results", {})
    test_regressions = parsed_test_results.get("_test_regressions", [])

    return VerificationRunResponse(
        id=run.id,
        finding_id=run.finding_id or "",
        patch_id=run.patch_id,
        baseline_hash=run.baseline_hash,
        patched_hash=run.patched_hash,
        scanner_metadata=safe_json_load(run.scanner_metadata, {}),
        scanner_config=safe_json_load(run.scanner_config, {}),
        tests_executed=safe_json_load(run.tests_executed, []),
        test_results=parsed_test_results,
        original_finding_status=run.original_finding_status or "untested",
        new_findings=safe_json_load(run.new_findings, []),
        classified_findings=classified_findings,
        baseline_test_results=baseline_test_results,
        test_regressions=test_regressions,
        execution_errors=safe_json_load(run.execution_errors, []),
        started_at=run.started_at,
        completed_at=run.completed_at,
        status=status_enum,
        reasons=safe_json_load(run.reasons, []),
        missing_evidence=safe_json_load(run.missing_evidence, []),
        evidence_references=safe_json_load(run.evidence_references, []),
        patch_diff=run.patch_diff,
        test_summary=run.test_summary,
        limitations=list(STANDARD_VERIFICATION_LIMITATIONS),
        evidence=evidence_schemas
    )
