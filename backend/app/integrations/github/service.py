"""GitHub App & CI/CD Integration Service Orchestrator.

Handles:
1. Installation registration with encrypted credential storage.
2. Repository-to-GitHub binding with operator security toggles.
3. PR security analysis pipeline (diff categorization, commit association).
4. Gated PR comment publication with permission checking and graceful revocation.
5. Ingestion of webhook events with signature and replay validation.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from ...core.audit import record_audit_event
from ...core.auth import verify_repository_ownership
from ...core.config import settings
from ...core.errors import ForbiddenError, NotFoundError, SecurityPolicyViolationError, UnauthorizedError, ValidationError
from ...core.ingestion import get_workspace_root
from ...core.logging import get_logger
from ...models.finding import SecurityFinding
from ...models.github import GitHubIntegration, PullRequestScan, RepositoryGitHubLink
from ...models.repository import Repository
from ...models.user import User
from .client import GitHubClient
from .crypto import compute_secret_digest, decrypt_credentials, encrypt_credentials
from .permissions import evaluate_installation_permissions
from .pr_analyzer import PRAnalysisResult, run_pr_security_analysis, sanitize_pr_untrusted_text
from .publisher import can_publish_pr_summary, generate_pr_summary_markdown
from .schemas import (
    CategorizedPRFinding,
    CIEvaluationRequest,
    CIEvaluationResponse,
    FindingClassification,
    GitHubInstallationRegisterRequest,
    GitHubInstallationResponse,
    PullRequestScanResponse,
    PullRequestScanTriggerRequest,
    RepositoryGitHubLinkRequest,
    RepositoryGitHubLinkResponse,
)
from .webhook import (
    claim_webhook_delivery,
    finalize_webhook_delivery,
    record_and_check_replay,
    verify_webhook_signature,
)

logger = get_logger("redmercury.github.service")


def register_github_installation(
    current_user: User,
    payload: GitHubInstallationRegisterRequest,
    db: Session,
) -> GitHubInstallationResponse:
    """Store GitHub App installation with encrypted credentials at rest."""
    # Validate permissions
    is_valid, missing, warnings = evaluate_installation_permissions(payload.permissions or {})
    if not is_valid:
        raise ValidationError(f"Insufficient GitHub permissions: {'; '.join(missing)}")

    # Check for existing installation ID for this user
    existing = db.query(GitHubIntegration).filter(
        GitHubIntegration.installation_id == payload.installation_id,
        GitHubIntegration.owner_id == current_user.id,
    ).first()

    # Build encrypted credentials dictionary (preserving prior secrets & supporting rotation)
    cred_dict: Dict[str, Any] = {}
    if existing and existing.encrypted_credentials:
        try:
            cred_dict.update(decrypt_credentials(existing.encrypted_credentials))
        except Exception:
            cred_dict = {}

    if payload.access_token:
        cred_dict["access_token"] = payload.access_token
    if payload.private_key_pem:
        cred_dict["private_key_pem"] = payload.private_key_pem
    if payload.webhook_secret:
        prior_secret = cred_dict.get("webhook_secret")
        if prior_secret and prior_secret != payload.webhook_secret:
            cred_dict["previous_webhook_secret"] = prior_secret
        cred_dict["webhook_secret"] = payload.webhook_secret

    encrypted_cred = encrypt_credentials(cred_dict) if cred_dict else None
    secret_hash = compute_secret_digest(payload.webhook_secret) if payload.webhook_secret else None

    if existing:
        existing.app_id = payload.app_id
        existing.account_login = payload.account_login
        existing.account_type = payload.account_type
        existing.auth_mode = payload.auth_mode
        if encrypted_cred:
            existing.encrypted_credentials = encrypted_cred
        if secret_hash:
            existing.webhook_secret_hash = secret_hash
        existing.permissions_granted = json.dumps(payload.permissions or {})
        existing.is_active = True
        existing.revoked_at = None
        db.commit()
        db.refresh(existing)
        installation_record = existing
    else:
        installation_record = GitHubIntegration(
            owner_id=current_user.id,
            installation_id=payload.installation_id,
            app_id=payload.app_id,
            account_login=payload.account_login,
            account_type=payload.account_type,
            auth_mode=payload.auth_mode,
            encrypted_credentials=encrypted_cred,
            webhook_secret_hash=secret_hash,
            permissions_granted=json.dumps(payload.permissions or {}),
            is_active=True,
        )
        db.add(installation_record)
        db.commit()
        db.refresh(installation_record)

    record_audit_event(
        db=db,
        action="GITHUB_INSTALLATION_REGISTERED",
        resource_type="github_installation",
        resource_identifier=installation_record.id,
        actor_id=current_user.id,
        metadata={"account_login": payload.account_login, "installation_id": payload.installation_id},
    )

    return _format_installation_response(installation_record)


def list_user_github_installations(
    current_user: User,
    db: Session,
) -> List[GitHubInstallationResponse]:
    """List active GitHub installations for the authenticated user."""
    records = db.query(GitHubIntegration).filter(
        GitHubIntegration.owner_id == current_user.id,
        GitHubIntegration.is_active == True,
    ).all()
    return [_format_installation_response(r) for r in records]


def revoke_github_installation(
    installation_id: str,
    current_user: User,
    db: Session,
    reason: str = "Operator revoked integration",
) -> GitHubInstallationResponse:
    """Revoke integration access and deactivate associated links."""
    record = db.query(GitHubIntegration).filter(
        (GitHubIntegration.id == installation_id) | (GitHubIntegration.installation_id == installation_id),
        GitHubIntegration.owner_id == current_user.id,
    ).first()

    if not record:
        raise NotFoundError(f"GitHub integration '{installation_id}' not found.")

    record.is_active = False
    record.revoked_at = datetime.now(timezone.utc)
    record.revocation_reason = reason
    db.commit()
    db.refresh(record)

    record_audit_event(
        db=db,
        action="GITHUB_INSTALLATION_REVOKED",
        resource_type="github_installation",
        resource_identifier=record.id,
        actor_id=current_user.id,
        metadata={"reason": reason},
    )

    return _format_installation_response(record)


def link_repository_to_github(
    current_user: User,
    payload: RepositoryGitHubLinkRequest,
    db: Session,
) -> RepositoryGitHubLinkResponse:
    """Bind a user-owned Red Mercury repository to a GitHub repository."""
    # 1. Enforce tenant ownership of the Red Mercury repository
    repo = verify_repository_ownership(repo_id=payload.repository_id, current_user=current_user, db=db)

    # 2. Enforce ownership of the integration
    integration = db.query(GitHubIntegration).filter(
        GitHubIntegration.id == payload.installation_id,
        GitHubIntegration.owner_id == current_user.id,
    ).first()
    if not integration or not integration.is_active:
        raise ValidationError("Selected GitHub integration is invalid, inactive, or belongs to another user.")

    # 3. Check existing link
    link = db.query(RepositoryGitHubLink).filter(
        RepositoryGitHubLink.repository_id == payload.repository_id
    ).first()

    if link:
        link.integration_id = payload.installation_id
        link.github_repo_full_name = payload.github_repo_full_name
        link.default_branch = payload.default_branch
        link.auto_scan_on_pr = payload.auto_scan_on_pr
        link.publish_pr_comments = payload.publish_pr_comments
        link.block_pr_on_critical = payload.block_pr_on_critical
    else:
        link = RepositoryGitHubLink(
            repository_id=payload.repository_id,
            integration_id=payload.installation_id,
            github_repo_full_name=payload.github_repo_full_name,
            default_branch=payload.default_branch,
            auto_scan_on_pr=payload.auto_scan_on_pr,
            publish_pr_comments=payload.publish_pr_comments,
            block_pr_on_critical=payload.block_pr_on_critical,
        )
        db.add(link)

    db.commit()
    db.refresh(link)

    record_audit_event(
        db=db,
        action="REPOSITORY_GITHUB_LINKED",
        resource_type="repository",
        resource_identifier=repo.id,
        actor_id=current_user.id,
        metadata={
            "github_repo": payload.github_repo_full_name,
            "publish_pr_comments": payload.publish_pr_comments,
        },
    )

    return RepositoryGitHubLinkResponse.model_validate(link)


def trigger_pr_security_scan(
    current_user: User,
    payload: PullRequestScanTriggerRequest,
    db: Session,
) -> PullRequestScanResponse:
    """Execute PR security analysis correlating findings across commits."""
    # 1. Enforce tenant authorization
    if not payload.repository_id and payload.link_id:
        link = db.query(RepositoryGitHubLink).filter(RepositoryGitHubLink.id == payload.link_id).first()
        if not link:
            raise NotFoundError(f"Repository GitHub Link '{payload.link_id}' not found.")
        payload.repository_id = link.repository_id

    if not payload.repository_id:
        raise ValidationError("Either repository_id or link_id is required to trigger PR scan.")

    repo = verify_repository_ownership(repo_id=payload.repository_id, current_user=current_user, db=db)

    # 2. Determine changed files with strict workspace confinement and symlink rejection (Task 5)
    changed_files = payload.changed_files or []
    if not changed_files and repo.workspace_path:
        raw_ws = Path(repo.workspace_path)
        if raw_ws.is_symlink():
            raise SecurityPolicyViolationError("Repository workspace path cannot be a symbolic link.")
        p = raw_ws.resolve(strict=False)
        workspace_root = get_workspace_root().resolve()
        if p == workspace_root or not p.is_relative_to(workspace_root):
            raise SecurityPolicyViolationError("Repository workspace path resolves outside authorized workspace root.")
        if p.exists() and p.is_dir():
            safe_files: List[str] = []
            for f in p.rglob("*"):
                if f.is_symlink() or not f.is_file():
                    continue
                resolved_f = f.resolve(strict=False)
                if not resolved_f.is_relative_to(p):
                    continue
                safe_files.append(str(resolved_f.relative_to(p)).replace("\\", "/"))
                if len(safe_files) >= 100:
                    break
            changed_files = safe_files

    # 3. Create scan tracking record
    pr_scan = PullRequestScan(
        repository_id=repo.id,
        pr_number=payload.pr_number,
        pr_title=sanitize_pr_untrusted_text(payload.pr_title),
        head_commit_sha=payload.head_commit_sha,
        base_commit_sha=payload.base_commit_sha,
        head_branch=payload.head_branch,
        base_branch=payload.base_branch,
        status="analyzing",
        changed_files=json.dumps(changed_files),
    )
    db.add(pr_scan)
    db.commit()
    db.refresh(pr_scan)

    # 4. Execute PR security analysis
    analysis_result = run_pr_security_analysis(
        repo=repo,
        head_commit_sha=payload.head_commit_sha,
        base_commit_sha=payload.base_commit_sha,
        changed_files=changed_files,
        db=db,
        selected_tools=payload.selected_tools,
    )

    # 5. Persist diff findings and metadata
    findings_dicts = [f.model_dump() for f in analysis_result.categorized_findings]
    pr_scan.status = analysis_result.status
    pr_scan.new_findings_count = analysis_result.new_count
    pr_scan.resolved_findings_count = analysis_result.resolved_count
    pr_scan.unchanged_findings_count = analysis_result.unchanged_count
    pr_scan.regressed_findings_count = analysis_result.regressed_count
    pr_scan.findings_diff_json = json.dumps(findings_dicts)
    pr_scan.incomplete_checks = json.dumps(analysis_result.incomplete_checks)
    pr_scan.execution_log = analysis_result.execution_log
    pr_scan.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(pr_scan)

    # 6. Auto-publish PR comment if enabled on link and permissions are satisfied
    link = db.query(RepositoryGitHubLink).filter(RepositoryGitHubLink.repository_id == repo.id).first()
    if link and link.publish_pr_comments:
        try:
            publish_pr_summary_comment(current_user=current_user, pr_scan_id=pr_scan.id, db=db)
        except Exception as exc:
            logger.warning(f"Auto-publishing PR comment skipped or failed: {str(exc)}")

    record_audit_event(
        db=db,
        action="PR_SECURITY_SCAN_COMPLETED",
        resource_type="pr_scan",
        resource_identifier=pr_scan.id,
        actor_id=current_user.id,
        metadata={
            "repo_id": repo.id,
            "pr_number": pr_scan.pr_number,
            "new_count": pr_scan.new_findings_count,
            "resolved_count": pr_scan.resolved_findings_count,
        },
    )

    return _format_pr_scan_response(pr_scan)


def get_pr_scan_details(
    pr_scan_id: str,
    current_user: User,
    db: Session,
) -> PullRequestScanResponse:
    """Retrieve full PR scan report with categorized findings and commit associations."""
    pr_scan = db.query(PullRequestScan).filter(PullRequestScan.id == pr_scan_id).first()
    if not pr_scan:
        raise NotFoundError(f"Pull request scan '{pr_scan_id}' not found.")

    verify_repository_ownership(repo_id=pr_scan.repository_id, current_user=current_user, db=db)
    return _format_pr_scan_response(pr_scan)


def publish_pr_summary_comment(
    current_user: User,
    pr_scan_id: str,
    db: Session,
    client_override: Optional[GitHubClient] = None,
) -> PullRequestScanResponse:
    """Publish a markdown security summary comment to the GitHub Pull Request."""
    pr_scan = db.query(PullRequestScan).filter(PullRequestScan.id == pr_scan_id).first()
    if not pr_scan:
        raise NotFoundError(f"PR scan '{pr_scan_id}' not found.")

    repo = verify_repository_ownership(repo_id=pr_scan.repository_id, current_user=current_user, db=db)

    # Resolve GitHub link
    link = db.query(RepositoryGitHubLink).filter(RepositoryGitHubLink.repository_id == repo.id).first()
    if not link:
        raise ValidationError(f"Repository '{repo.name}' is not connected to GitHub.")

    integration = db.query(GitHubIntegration).filter(GitHubIntegration.id == link.integration_id).first()
    if not integration or not integration.is_active:
        raise ValidationError("GitHub integration credentials are inactive or revoked.")

    perms = json.loads(integration.permissions_granted or "{}")

    # Enforce permission and operator policy gate
    can_publish, reject_reason = can_publish_pr_summary(
        link_publish_toggle=link.publish_pr_comments,
        granted_permissions=perms,
    )
    if not can_publish:
        raise SecurityPolicyViolationError(reject_reason or "PR summary publishing not permitted.")

    # Reconstruct analysis result for formatting
    findings_list = [CategorizedPRFinding.model_validate(f) for f in json.loads(pr_scan.findings_diff_json or "[]")]
    incomplete_list = json.loads(pr_scan.incomplete_checks or "[]")
    changed_files_list = json.loads(pr_scan.changed_files or "[]")

    analysis_res = PRAnalysisResult(
        head_commit_sha=pr_scan.head_commit_sha,
        base_commit_sha=pr_scan.base_commit_sha,
        status=pr_scan.status,
        changed_files=changed_files_list,
        categorized_findings=findings_list,
        new_count=pr_scan.new_findings_count,
        resolved_count=pr_scan.resolved_findings_count,
        unchanged_count=pr_scan.unchanged_findings_count,
        regressed_count=pr_scan.regressed_findings_count,
        scanners_executed=["Bandit", "Semgrep OSS", "pip-audit"],
        incomplete_checks=incomplete_list,
    )

    markdown_comment = generate_pr_summary_markdown(
        repo_name=link.github_repo_full_name,
        pr_number=pr_scan.pr_number,
        head_sha=pr_scan.head_commit_sha,
        analysis=analysis_res,
    )

    # Post via GitHub Client
    client = client_override
    if not client:
        creds = decrypt_credentials(integration.encrypted_credentials or "")
        token = creds.get("access_token")
        if not token:
            raise ValidationError("No valid access token available in decrypted integration credentials.")
        client = GitHubClient(token=token)

    try:
        api_res = client.post_pr_comment(
            repo_full_name=link.github_repo_full_name,
            pr_number=pr_scan.pr_number,
            comment_body=markdown_comment,
        )
        pr_scan.summary_published = True
        pr_scan.summary_comment_id = str(api_res.get("id", "comment-posted"))
        db.commit()
        db.refresh(pr_scan)

        record_audit_event(
            db=db,
            action="PR_SUMMARY_COMMENT_PUBLISHED",
            resource_type="pr_scan",
            resource_identifier=pr_scan.id,
            actor_id=current_user.id,
            metadata={"github_repo": link.github_repo_full_name, "pr_number": pr_scan.pr_number},
        )
        return _format_pr_scan_response(pr_scan)
    except Exception as exc:
        if "revoked" in str(exc).lower() or "expired" in str(exc).lower():
            # Automatically deactivate revoked integration
            integration.is_active = False
            integration.revoked_at = datetime.now(timezone.utc)
            integration.revocation_reason = "GitHub rejected token as invalid or revoked"
            db.commit()
        raise exc


def handle_incoming_webhook(
    event_type: str,
    delivery_id: Optional[str],
    signature_header: Optional[str],
    raw_payload: bytes,
    db: Session,
) -> Dict[str, Any]:
    """Validate and process incoming GitHub webhook events with pre-persistence HMAC and replay defense (SEC-12).

    Security invariants:
    1. Rejects missing/malformed X-Hub-Signature-256 or missing X-GitHub-Delivery BEFORE any DB write.
    2. Resolves installation-specific secret (supporting active + rotated previous secret) without cross-installation fallback.
    3. Verifies HMAC-SHA256 over raw request bytes in constant time BEFORE persisting WebhookDelivery.
    4. Atomically claims delivery_id with status='processing' (concurrency-safe idempotency) and finalizes to 'completed' or 'failed'.
    """
    # 1. Pre-persistence header & signature format validation (zero DB writes on invalid headers)
    if not delivery_id or not str(delivery_id).strip():
        raise SecurityPolicyViolationError("Missing X-GitHub-Delivery header (required for replay defense).")

    if not signature_header:
        raise UnauthorizedError("Missing X-Hub-Signature-256 header for webhook verification.")

    if not signature_header.startswith("sha256="):
        raise UnauthorizedError("Invalid signature algorithm; sha256 is required.")

    # 2. Parse JSON payload safely before DB persistence
    try:
        payload_json = json.loads(raw_payload.decode("utf-8"))
        if not isinstance(payload_json, dict):
            raise ValueError("Payload root must be a JSON object")
    except Exception:
        raise ValidationError("Malformed JSON payload in webhook body.")

    # 3. Resolve target installation strictly by installation.id or linked repository.full_name
    inst_obj = payload_json.get("installation")
    installation_id = str(inst_obj.get("id", "")).strip() if isinstance(inst_obj, dict) else ""
    repo_obj = payload_json.get("repository")
    repo_full_name = repo_obj.get("full_name") if isinstance(repo_obj, dict) else None

    integration: Optional[GitHubIntegration] = None
    if installation_id:
        integration = db.query(GitHubIntegration).filter(
            GitHubIntegration.installation_id == installation_id,
            GitHubIntegration.is_active == True,
        ).first()
        if integration is None:
            # Do not fall back to another installation's secret when an explicit installation_id was supplied
            active_installations_count = db.query(GitHubIntegration).filter(
                GitHubIntegration.is_active == True
            ).count()
            if active_installations_count > 0:
                raise UnauthorizedError("Unknown or inactive GitHub installation for webhook delivery.")

    if integration is None and repo_full_name:
        link = db.query(RepositoryGitHubLink).filter(
            RepositoryGitHubLink.github_repo_full_name == repo_full_name
        ).first()
        if link and link.integration and link.integration.is_active:
            integration = link.integration

    # 4. Resolve candidate secret(s) bound strictly to the resolved installation
    candidate_secrets: List[str] = []
    has_installation_secret = False
    if integration is not None:
        if integration.encrypted_credentials:
            try:
                creds = decrypt_credentials(integration.encrypted_credentials)
                if creds.get("webhook_secret"):
                    candidate_secrets.append(str(creds["webhook_secret"]))
                    has_installation_secret = True
                if creds.get("previous_webhook_secret"):
                    candidate_secrets.append(str(creds["previous_webhook_secret"]))
                    has_installation_secret = True
            except Exception:
                pass
        if integration.webhook_secret_hash and not has_installation_secret:
            has_installation_secret = True

    # Only fall back to server-level GITHUB_WEBHOOK_SECRET if the installation did not configure its own secret
    if not has_installation_secret and settings.GITHUB_WEBHOOK_SECRET:
        candidate_secrets.append(settings.GITHUB_WEBHOOK_SECRET)

    if not candidate_secrets:
        raise UnauthorizedError("GitHub webhook verification secret is not configured on this installation or server.")

    # 5. Verify HMAC-SHA256 over raw_payload BEFORE recording WebhookDelivery (prevents unauthenticated DB poisoning)
    signature_valid = any(
        verify_webhook_signature(raw_payload, signature_header, secret)
        for secret in candidate_secrets
    )
    if not signature_valid:
        raise UnauthorizedError("Invalid GitHub webhook signature.")

    # 6. Atomically claim delivery ID (idempotent & race-safe across concurrent duplicate deliveries)
    is_fresh, replay_err = claim_webhook_delivery(
        db=db,
        delivery_id=delivery_id,
        event_type=event_type,
        raw_payload=raw_payload,
    )
    if not is_fresh:
        raise SecurityPolicyViolationError(replay_err or "Webhook delivery rejected as replay.")

    # 7. Process authenticated event with failure-safe delivery state tracking
    try:
        if payload_json.get("_simulate_processing_failure"):
            raise RuntimeError("Simulated webhook processing failure")

        finalize_webhook_delivery(db=db, delivery_id=str(delivery_id), status="completed")
        return {
            "status": "completed",
            "delivery_id": str(delivery_id).strip(),
            "event_type": event_type,
            "repo": repo_full_name,
            "installation_id": installation_id or None,
            "processed": True,
        }
    except Exception:
        finalize_webhook_delivery(db=db, delivery_id=str(delivery_id), status="failed")
        raise


def _format_installation_response(rec: GitHubIntegration) -> GitHubInstallationResponse:
    perms = json.loads(rec.permissions_granted) if rec.permissions_granted else {}
    return GitHubInstallationResponse(
        id=rec.id,
        owner_id=rec.owner_id,
        installation_id=rec.installation_id,
        app_id=rec.app_id,
        account_login=rec.account_login,
        account_type=rec.account_type,
        auth_mode=rec.auth_mode,
        is_active=rec.is_active,
        permissions_granted=perms,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


def _format_pr_scan_response(pr_scan: PullRequestScan) -> PullRequestScanResponse:
    findings_raw = json.loads(pr_scan.findings_diff_json or "[]")
    findings = [CategorizedPRFinding.model_validate(f) for f in findings_raw]
    incomplete = json.loads(pr_scan.incomplete_checks or "[]")
    changed_files = json.loads(pr_scan.changed_files or "[]")

    return PullRequestScanResponse(
        id=pr_scan.id,
        repository_id=pr_scan.repository_id,
        pr_number=pr_scan.pr_number,
        pr_title=pr_scan.pr_title,
        head_commit_sha=pr_scan.head_commit_sha,
        base_commit_sha=pr_scan.base_commit_sha,
        status=pr_scan.status,
        changed_files=changed_files,
        new_findings_count=pr_scan.new_findings_count,
        resolved_findings_count=pr_scan.resolved_findings_count,
        unchanged_findings_count=pr_scan.unchanged_findings_count,
        regressed_findings_count=pr_scan.regressed_findings_count,
        findings=findings,
        summary_published=pr_scan.summary_published,
        summary_comment_id=pr_scan.summary_comment_id,
        incomplete_checks=incomplete,
        failed_checks=[],
        unavailable_checks=incomplete,
        verifications=[],
        reproduction_command=f"python -m scripts.ci_security_gate --repo-path . --head-sha {pr_scan.head_commit_sha[:8]} --base-sha {pr_scan.base_commit_sha[:8]}",
        report_links={
            "repository": f"/repositories/{pr_scan.repository_id}",
            "findings": f"/repositories/{pr_scan.repository_id}/findings",
        },
        started_at=pr_scan.started_at,
        completed_at=pr_scan.completed_at,
    )


def evaluate_ci_security_gate(
    current_user: User,
    payload: CIEvaluationRequest,
    db: Session,
) -> CIEvaluationResponse:
    """Evaluate repository commit against security gating policy for CI/CD pipelines."""
    # 1. Resolve repository
    repo = None
    if payload.repository_id:
        repo = db.query(Repository).filter(
            (Repository.id == payload.repository_id) | (Repository.name == payload.repository_id)
        ).first()
        if not repo:
            raise NotFoundError(f"Repository '{payload.repository_id}' not found.")
        verify_repository_ownership(repo_id=repo.id, current_user=current_user, db=db)
    else:
        # Default to user's first available repository
        repo = db.query(Repository).filter(Repository.owner_id == current_user.id).first()
        if not repo:
            raise NotFoundError("No repository found for the current user.")

    # 2. Run PR / CI security analysis
    analysis = run_pr_security_analysis(
        repo=repo,
        head_commit_sha=payload.head_commit_sha,
        base_commit_sha=payload.base_commit_sha or "BASE",
        changed_files=payload.changed_files or [],
        db=db,
        selected_tools=payload.selected_tools,
    )

    # 3. Apply CI Gate Policy
    sev_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    threshold_str = (payload.fail_on_severity or "HIGH").upper()
    threshold_level = sev_levels.get(threshold_str, 3)

    policy_violations: List[str] = []
    for f in analysis.categorized_findings:
        if f.classification in (FindingClassification.NEW, FindingClassification.REGRESSED):
            f_level = sev_levels.get(f.severity.upper(), 1)
            if f_level >= threshold_level:
                policy_violations.append(f"{f.classification.value}: {f.severity} '{f.rule_id}' in {f.file_path}")

    # Decision logic
    has_unavailable = bool(analysis.unavailable_checks or (analysis.incomplete_checks and payload.require_all_checks))
    has_failures = bool(policy_violations or analysis.failed_checks)

    if has_unavailable and payload.require_all_checks:
        gate_status = "INCOMPLETE"
        exit_code = 2
        gate_passed = False
    elif has_failures:
        gate_status = "FAIL"
        exit_code = 1
        gate_passed = False
    else:
        gate_status = "PASS"
        exit_code = 0
        gate_passed = True

    # 4. Generate PR summary markdown
    summary_md = generate_pr_summary_markdown(
        repo_name=repo.name,
        pr_number=payload.pr_number or 0,
        head_sha=payload.head_commit_sha,
        analysis=analysis,
    )

    record_audit_event(
        db=db,
        action="CI_SECURITY_GATE_EVALUATED",
        resource_type="ci_gate",
        resource_identifier=f"{repo.id}:{payload.head_commit_sha[:8]}",
        actor_id=current_user.id,
        metadata={
            "gate_status": gate_status,
            "exit_code": exit_code,
            "violations_count": len(policy_violations),
            "unavailable_count": len(analysis.unavailable_checks),
        },
    )

    all_failed_checks = list(dict.fromkeys(analysis.failed_checks + policy_violations))

    return CIEvaluationResponse(
        repository_id=repo.id,
        repository_name=repo.name,
        head_commit_sha=payload.head_commit_sha,
        base_commit_sha=payload.base_commit_sha,
        pr_number=payload.pr_number,
        gate_status=gate_status,
        exit_code=exit_code,
        gate_passed=gate_passed,
        summary_markdown=summary_md,
        new_findings_count=analysis.new_count,
        resolved_findings_count=analysis.resolved_count,
        regressed_findings_count=analysis.regressed_count,
        unchanged_findings_count=analysis.unchanged_count,
        failed_checks=all_failed_checks,
        unavailable_checks=analysis.unavailable_checks,
        findings=analysis.categorized_findings,
        verifications=analysis.verification_summaries,
        reproduction_command=analysis.reproduction_command or f"python -m scripts.ci_security_gate --repo-path . --head-sha {payload.head_commit_sha[:8]}",
        report_links=analysis.report_links,
    )
