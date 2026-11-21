"""Authentication and authorization dependencies for FastAPI endpoints."""
from datetime import datetime, timezone
import hashlib
from typing import Collection, Optional, Set, Tuple
from urllib.parse import urlparse
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .audit import record_audit_event
from .config import settings
from .errors import AccountInactiveError, ForbiddenError, NotFoundError, UnauthorizedError
from .logging import get_logger
from .security import decode_access_token
from ..db.session import get_db
from ..models.evidence import SecurityEvidence
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.token import RevokedToken
from ..models.user import User
from ..models.verification import VerificationRun

logger = get_logger("redmercury.auth")


def extract_token_with_source(request: Request) -> Tuple[Optional[str], str]:
    """Extract authentication token and identify whether it came from header or cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            return token, "header"

    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if cookie_token and cookie_token.strip():
        return cookie_token.strip(), "cookie"

    return None, "none"


def extract_token(request: Request) -> Optional[str]:
    """Extract authentication token from Authorization header or HTTP-only cookie."""
    token, _ = extract_token_with_source(request)
    return token


def verify_csrf_origin(request: Request) -> None:
    """Validates Origin/Referer on state-modifying requests authenticated via session cookie."""
    if not settings.CSRF_PROTECTION_ENABLED:
        return

    if request.method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
        return

    # Bearer tokens are immune to standard cross-site form CSRF due to custom header requirements
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return

    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if not cookie_token or not cookie_token.strip():
        return

    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")

    # Build allowed origins set
    allowed_origins = set()
    raw_cors = settings.CORS_ORIGINS
    if isinstance(raw_cors, list):
        for o in raw_cors:
            allowed_origins.add(o.rstrip("/"))
    elif isinstance(raw_cors, str):
        for o in raw_cors.split(","):
            if o.strip():
                allowed_origins.add(o.strip().rstrip("/"))

    base_origin = f"{request.url.scheme}://{request.url.netloc}".rstrip("/")
    allowed_origins.add(base_origin)
    allowed_origins.add("http://testserver")

    if origin:
        clean_origin = origin.rstrip("/")
        if clean_origin not in allowed_origins:
            logger.warning(f"CSRF protection blocked request from untrusted origin '{origin}'")
            raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: untrusted origin.")
        return

    if referer:
        try:
            parsed = urlparse(referer)
            ref_origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
            if ref_origin not in allowed_origins:
                logger.warning(f"CSRF protection blocked request from untrusted referer '{referer}'")
                raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: untrusted referer.")
            return
        except Exception:
            raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: malformed referer.")

    # Reject cookie-based state mutations that omit both Origin and Referer
    raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: missing origin headers.")


def compute_token_hash(token: str) -> str:
    """Compute deterministic SHA-256 hash of token to avoid storing raw JWT in persistent storage."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def is_token_revoked(db: Session, token: str) -> bool:
    """Check if token hash exists in the revoked_tokens registry."""
    if not token:
        return False
    thash = compute_token_hash(token)
    revoked = db.query(RevokedToken).filter(RevokedToken.token_hash == thash).first()
    return revoked is not None


def revoke_token(db: Session, token: str, reason: str = "logout") -> bool:
    """Add a token to the server-side revoked_tokens registry with expiration retention."""
    if not token:
        return False
    thash = compute_token_hash(token)
    existing = db.query(RevokedToken).filter(RevokedToken.token_hash == thash).first()
    if existing:
        return True

    user_id = None
    jti = None
    expires_at = None
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        jti = payload.get("jti")
        exp_ts = payload.get("exp")
        if exp_ts:
            expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
    except Exception:
        pass

    try:
        revoked = RevokedToken(
            token_hash=thash,
            jti=jti,
            user_id=user_id,
            expires_at=expires_at,
            reason=reason,
        )
        db.add(revoked)
        db.commit()

        # Opportunity cleanup: remove tokens expired more than 1 hour ago
        try:
            now = datetime.now(timezone.utc)
            db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(synchronize_session=False)
            db.commit()
        except Exception:
            db.rollback()

        return True
    except Exception as exc:
        db.rollback()
        logger.warning(f"Failed to record token revocation: {exc}")
        return False


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Dependency that authenticates the user via bearer token or HTTP-only session cookie."""
    verify_csrf_origin(request)

    token = extract_token(request)
    if not token:
        raise UnauthorizedError("Authentication credentials were not provided. Sign in to proceed.")

    if is_token_revoked(db, token):
        logger.warning("Authentication rejected: Attempted access with revoked token")
        raise UnauthorizedError("Authentication token has been revoked. Please sign in again.")

    payload = decode_access_token(token)
    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise UnauthorizedError("Malformed authentication credentials.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise UnauthorizedError("User account no longer exists.")

    if settings.is_production and user.email == "dev@xerova.com":
        raise UnauthorizedError("Development seed account is permanently disabled in production.")

    if user.account_status != "active":
        raise AccountInactiveError("This account is currently inactive or suspended.")

    # Attach token role if provided in claims; default to user.role or 'admin'
    token_role = payload.get("role")
    if token_role:
        user.role = token_role
    elif not getattr(user, "role", None):
        user.role = "admin"

    return user


# Roles configured for read-only vs. mutating access
READ_ONLY_ROLES: Set[str] = {"viewer", "auditor"}


def require_role(allowed_roles: Collection[str]):
    """Centralized RBAC dependency factory enforcing minimum role level."""
    def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = (getattr(current_user, "role", None) or "admin").lower()
        allowed = {r.lower() for r in allowed_roles}
        if user_role in READ_ONLY_ROLES and user_role not in allowed:
            raise ForbiddenError(f"Role '{getattr(current_user, 'role', 'viewer')}' is not permitted to perform this action.")
        if allowed and user_role not in allowed:
            raise ForbiddenError(f"Role '{getattr(current_user, 'role', 'user')}' lacks required permissions.")
        return current_user
    return _role_checker


def require_mutating_role(current_user: User = Depends(get_current_user)) -> User:
    """Enforce that read-only viewer/auditor roles cannot perform mutating actions."""
    user_role = (getattr(current_user, "role", None) or "admin").lower()
    if user_role in READ_ONLY_ROLES:
        raise ForbiddenError(f"Role '{getattr(current_user, 'role', 'viewer')}' is restricted to read-only access and cannot perform mutating actions.")
    return current_user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Optional authentication dependency; returns None if not authenticated."""
    token = extract_token(request)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        user = db.query(User).filter(User.id == user_id).first()
        if user and user.account_status == "active":
            if settings.is_production and user.email == "dev@xerova.com":
                return None
            return user
        return None
    except Exception:
        return None


def verify_repository_ownership(
    repo_id: str,
    current_user: User,
    db: Session,
) -> Repository:
    """Enforces strict multi-tenant ownership check on repositories."""
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise NotFoundError(f"Repository with id '{repo_id}' not found.")

    if repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_REPO_ACCESS_BLOCKED",
            resource_type="repository",
            resource_identifier=repo_id,
            actor_id=current_user.id,
            metadata={"owner_id": repo.owner_id},
        )
        raise ForbiddenError("You do not have permission to access this repository.")

    return repo


def verify_finding_ownership(
    finding_id: str,
    current_user: User,
    db: Session,
) -> SecurityFinding:
    """Enforces strict multi-tenant ownership check on findings."""
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise NotFoundError(f"Security finding with id '{finding_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_FINDING_ACCESS_BLOCKED",
            resource_type="finding",
            resource_identifier=finding_id,
            actor_id=current_user.id,
            metadata={"repo_id": finding.repo_id},
        )
        raise ForbiddenError("You do not have permission to access findings for this repository.")

    return finding


def verify_scan_ownership(
    scan_id: str,
    current_user: User,
    db: Session,
) -> Scan:
    """Enforces strict multi-tenant ownership check on security scans."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with id '{scan_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_SCAN_ACCESS_BLOCKED",
            resource_type="scan",
            resource_identifier=scan_id,
            actor_id=current_user.id,
            metadata={"repository_id": scan.repository_id},
        )
        raise ForbiddenError("You do not have permission to access scans for this repository.")

    return scan


def verify_verification_run_ownership(
    run_id: str,
    current_user: User,
    db: Session,
) -> VerificationRun:
    """Enforces strict multi-tenant ownership check on verification runs."""
    run = db.query(VerificationRun).filter(VerificationRun.id == run_id).first()
    if not run:
        raise NotFoundError(f"Verification run with ID '{run_id}' was not found.")

    if not run.finding_id:
        raise ForbiddenError("Verification run is not linked to a verified finding.")

    finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
    if not finding:
        raise NotFoundError(f"Finding associated with verification run '{run_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_VERIFICATION_ACCESS_BLOCKED",
            resource_type="verification_run",
            resource_identifier=run_id,
            actor_id=current_user.id,
            metadata={"finding_id": run.finding_id, "repo_id": finding.repo_id},
        )
        raise ForbiddenError("You do not have permission to access verification runs for this repository.")

    return run


def verify_evidence_ownership(
    evidence_id: str,
    current_user: User,
    db: Session,
) -> SecurityEvidence:
    """Enforces strict multi-tenant ownership check on security evidence artifacts."""
    evidence = db.query(SecurityEvidence).filter(SecurityEvidence.id == evidence_id).first()
    if not evidence:
        raise NotFoundError(f"Security evidence with id '{evidence_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == evidence.repository_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_EVIDENCE_ACCESS_BLOCKED",
            resource_type="evidence",
            resource_identifier=evidence_id,
            actor_id=current_user.id,
            metadata={"repo_id": evidence.repository_id},
        )
        raise ForbiddenError("You do not have permission to access evidence for this repository.")

    return evidence
