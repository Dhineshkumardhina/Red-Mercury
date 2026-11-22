"""Authentication and authorization dependencies for FastAPI endpoints."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Collection, Optional, Set, Tuple
from urllib.parse import urlparse
import uuid
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .audit import record_audit_event
from .config import settings
from .errors import AccountInactiveError, ForbiddenError, NotFoundError, SessionExpiredError, UnauthorizedError
from .logging import get_logger
from .security import decode_access_token
from ..db.session import get_db
from ..models.evidence import SecurityEvidence
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.token import RefreshTokenSession, RevokedToken
from ..models.user import User
from ..models.verification import VerificationRun
from ..schemas.auth import UserRole

logger = get_logger("redmercury.auth")

VALID_ROLES: Set[str] = {r.value for r in UserRole}


def generate_csrf_token() -> str:
    """Generate a cryptographically secure double-submit CSRF token."""
    return secrets.token_urlsafe(32)


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


def verify_csrf_origin(request: Request, force_cookie_check: bool = False) -> None:
    """Validate Origin/Referer and double-submit X-CSRF-Token on cookie-authenticated state mutations."""
    if not settings.CSRF_PROTECTION_ENABLED:
        return

    if request.method.upper() not in ("POST", "PUT", "DELETE", "PATCH"):
        return

    # Bearer tokens are immune to cross-site cookie CSRF unless forced (e.g. cookie-only refresh)
    if not force_cookie_check:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            return

    access_cookie = request.cookies.get(settings.COOKIE_NAME)
    refresh_cookie = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not force_cookie_check and not (access_cookie and access_cookie.strip()) and not (refresh_cookie and refresh_cookie.strip()):
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
    # Never trust http://testserver in staging or production (SEC-17)
    if not settings.is_strict_env:
        allowed_origins.add("http://testserver")

    origin_verified = False
    if origin:
        clean_origin = origin.rstrip("/")
        if clean_origin not in allowed_origins:
            logger.warning(f"CSRF protection blocked request from untrusted origin '{origin}'")
            raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: untrusted origin.")
        origin_verified = True
    elif referer:
        try:
            parsed = urlparse(referer)
            ref_origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
            if ref_origin not in allowed_origins:
                logger.warning(f"CSRF protection blocked request from untrusted referer '{referer}'")
                raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: untrusted referer.")
            origin_verified = True
        except ForbiddenError:
            raise
        except Exception:
            raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: malformed referer.")

    if not origin_verified:
        raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: missing origin headers.")

    # Double-submit CSRF token validation whenever the CSRF cookie is present
    csrf_cookie = (request.cookies.get(settings.CSRF_COOKIE_NAME) or "").strip()
    if csrf_cookie:
        csrf_header = (request.headers.get("X-CSRF-Token") or "").strip()
        if not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            logger.warning("CSRF protection blocked request: missing or mismatched X-CSRF-Token header")
            raise ForbiddenError("Cross-Site Request Forgery (CSRF) verification failed: invalid CSRF token.")


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
    """Add a validated token to the server-side revoked_tokens registry with expiration retention.

    Rejects malformed/unverifiable tokens so unauthenticated callers cannot bloat revoked_tokens (SEC-07).
    """
    if not token:
        return False

    try:
        payload = decode_access_token(token)
    except SessionExpiredError:
        # Already expired tokens need not be persisted
        return False
    except Exception:
        # Do not persist invalid/forged arbitrary strings into revoked_tokens
        return False

    thash = compute_token_hash(token)
    existing = db.query(RevokedToken).filter(RevokedToken.token_hash == thash).first()
    if existing:
        return True

    user_id = payload.get("sub")
    jti = payload.get("jti")
    exp_ts = payload.get("exp")
    expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else (
        datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

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

        # Opportunistic cleanup: remove already-expired revoked tokens
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


def issue_refresh_token_session(
    db: Session,
    user_id: str,
    family_id: Optional[str] = None,
    parent_token_hash: Optional[str] = None,
) -> Tuple[str, RefreshTokenSession]:
    """Mint a cryptographically random opaque refresh token and persist its SHA-256 hash."""
    raw_token = secrets.token_urlsafe(48)
    token_hash = compute_token_hash(raw_token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    session_row = RefreshTokenSession(
        family_id=family_id or str(uuid.uuid4()),
        user_id=user_id,
        token_hash=token_hash,
        parent_token_hash=parent_token_hash,
        expires_at=expires_at,
        created_at=now,
    )
    db.add(session_row)
    db.commit()
    db.refresh(session_row)
    return raw_token, session_row


def revoke_refresh_token_family(
    db: Session,
    raw_refresh_token: Optional[str] = None,
    family_id: Optional[str] = None,
    reason: str = "logout",
) -> int:
    """Revoke all active refresh tokens in a session family."""
    target_family = family_id
    if not target_family and raw_refresh_token:
        thash = compute_token_hash(raw_refresh_token)
        row = db.query(RefreshTokenSession).filter(RefreshTokenSession.token_hash == thash).first()
        if row:
            target_family = row.family_id

    if not target_family:
        return 0

    now = datetime.now(timezone.utc)
    updated = (
        db.query(RefreshTokenSession)
        .filter(
            RefreshTokenSession.family_id == target_family,
            RefreshTokenSession.revoked_at.is_(None),
        )
        .update(
            {"revoked_at": now, "revoke_reason": reason},
            synchronize_session=False,
        )
    )
    db.commit()
    return int(updated or 0)


def rotate_refresh_token_session(
    db: Session,
    raw_refresh_token: str,
) -> Tuple[User, str, RefreshTokenSession]:
    """Atomically rotate a refresh token with reuse/replay detection and DB-authoritative role checks."""
    if not raw_refresh_token or not raw_refresh_token.strip():
        raise UnauthorizedError("Refresh token is missing.")

    thash = compute_token_hash(raw_refresh_token)
    session_row = db.query(RefreshTokenSession).filter(RefreshTokenSession.token_hash == thash).first()
    if not session_row:
        raise UnauthorizedError("Invalid refresh session. Please sign in again.")

    now = datetime.now(timezone.utc)

    # Reuse / replay detection: a previously rotated or revoked token was presented again!
    if session_row.revoked_at is not None:
        revoke_refresh_token_family(db, family_id=session_row.family_id, reason="reuse_detected")
        record_audit_event(
            db=db,
            action="REFRESH_TOKEN_REUSE_DETECTED",
            resource_type="auth_session",
            resource_identifier=session_row.family_id,
            actor_id=session_row.user_id,
            metadata={"reason": "Presented already-revoked refresh token; entire family invalidated"},
        )
        raise UnauthorizedError("Refresh token reuse detected. Session family has been invalidated.")

    # Expiration check (handle naive SQLite datetimes defensively)
    expires_at = session_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        session_row.revoked_at = now
        session_row.revoke_reason = "expired"
        db.commit()
        raise SessionExpiredError("Refresh session has expired. Please sign in again.")

    # Atomic conditional UPDATE prevents concurrent refresh races from minting duplicate tokens
    new_raw_token = secrets.token_urlsafe(48)
    new_token_hash = compute_token_hash(new_raw_token)
    claimed = (
        db.query(RefreshTokenSession)
        .filter(
            RefreshTokenSession.id == session_row.id,
            RefreshTokenSession.revoked_at.is_(None),
        )
        .update(
            {
                "revoked_at": now,
                "revoke_reason": "rotated",
                "replaced_by_hash": new_token_hash,
            },
            synchronize_session=False,
        )
    )
    db.commit()

    if claimed != 1:
        # Lost concurrent race: do not issue a second token
        raise UnauthorizedError("Refresh token was already consumed by a concurrent request.")

    # Verify authoritative user state and DB role
    user = db.query(User).filter(User.id == session_row.user_id).first()
    if not user:
        revoke_refresh_token_family(db, family_id=session_row.family_id, reason="user_deleted")
        raise UnauthorizedError("User account no longer exists.")

    if settings.is_strict_env and user.email == "dev@xerova.com":
        revoke_refresh_token_family(db, family_id=session_row.family_id, reason="dev_seed_blocked")
        raise UnauthorizedError("Development seed account is permanently disabled in production.")

    if user.account_status != "active":
        revoke_refresh_token_family(db, family_id=session_row.family_id, reason="account_inactive")
        raise AccountInactiveError("This account is currently inactive or suspended.")

    db_role = (getattr(user, "role", None) or "").strip().lower()
    if db_role not in VALID_ROLES:
        revoke_refresh_token_family(db, family_id=session_row.family_id, reason="invalid_role")
        raise ForbiddenError("User account has an invalid role assignment.")

    # Persist rotated successor token in the same session family
    new_expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    new_session = RefreshTokenSession(
        family_id=session_row.family_id,
        user_id=user.id,
        token_hash=new_token_hash,
        parent_token_hash=thash,
        expires_at=new_expires_at,
        created_at=now,
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)

    return user, new_raw_token, new_session


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

    if settings.is_strict_env and user.email == "dev@xerova.com":
        raise UnauthorizedError("Development seed account is permanently disabled in production.")

    if user.account_status != "active":
        raise AccountInactiveError("This account is currently inactive or suspended.")

    # Database is strictly authoritative for user roles; never overwrite ORM role from JWT claims
    db_role = (getattr(user, "role", None) or "").strip().lower()
    if db_role not in VALID_ROLES:
        logger.warning(f"User '{user.id}' has invalid database role '{getattr(user, 'role', None)}'")
        raise ForbiddenError("User account has an invalid role assignment.")

    return user


# Roles configured for read-only vs. mutating access
READ_ONLY_ROLES: Set[str] = {UserRole.VIEWER.value, UserRole.AUDITOR.value}


def require_role(allowed_roles: Collection[str]):
    """Centralized RBAC dependency factory enforcing minimum role level from authoritative DB state."""
    def _role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_role = (getattr(current_user, "role", None) or UserRole.VIEWER.value).strip().lower()
        if user_role not in VALID_ROLES:
            raise ForbiddenError("User account has an invalid role assignment.")
        allowed = {r.lower() for r in allowed_roles}
        if user_role in READ_ONLY_ROLES and user_role not in allowed:
            raise ForbiddenError(f"Role '{user_role}' is not permitted to perform this action.")
        if allowed and user_role not in allowed:
            raise ForbiddenError(f"Role '{user_role}' lacks required permissions.")
        return current_user
    return _role_checker


def require_mutating_role(current_user: User = Depends(get_current_user)) -> User:
    """Enforce that read-only viewer/auditor roles cannot perform mutating actions."""
    user_role = (getattr(current_user, "role", None) or UserRole.VIEWER.value).strip().lower()
    if user_role not in VALID_ROLES or user_role in READ_ONLY_ROLES:
        raise ForbiddenError(f"Role '{user_role}' is restricted to read-only access and cannot perform mutating actions.")
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
            if settings.is_strict_env and user.email == "dev@xerova.com":
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


def verify_scan_belongs_to_repository(
    scan_id: str,
    repo_id: str,
    current_user: User,
    db: Session,
) -> Scan:
    """Enforce that scan_id exists, is owned by current_user, and belongs to repo_id (SEC-14)."""
    scan = verify_scan_ownership(scan_id=scan_id, current_user=current_user, db=db)
    if scan.repository_id != repo_id:
        record_audit_event(
            db=db,
            action="CROSS_REPOSITORY_SCAN_REFERENCE_BLOCKED",
            resource_type="scan",
            resource_identifier=scan_id,
            actor_id=current_user.id,
            metadata={"scan_repo_id": scan.repository_id, "target_repo_id": repo_id},
        )
        raise ForbiddenError("Referenced scan does not belong to the specified repository.")
    return scan


def verify_finding_belongs_to_repository(
    finding_id: str,
    repo_id: str,
    current_user: User,
    db: Session,
) -> SecurityFinding:
    """Enforce that finding_id exists, is owned by current_user, and belongs to repo_id (SEC-14)."""
    finding = verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    if finding.repo_id != repo_id:
        record_audit_event(
            db=db,
            action="CROSS_REPOSITORY_FINDING_REFERENCE_BLOCKED",
            resource_type="finding",
            resource_identifier=finding_id,
            actor_id=current_user.id,
            metadata={"finding_repo_id": finding.repo_id, "target_repo_id": repo_id},
        )
        raise ForbiddenError("Referenced security finding does not belong to the specified repository.")
    return finding


def verify_verification_run_belongs_to_repository(
    run_id: str,
    repo_id: str,
    current_user: User,
    db: Session,
    finding_id: Optional[str] = None,
) -> VerificationRun:
    """Enforce that verification_run_id exists, is owned by current_user, and belongs to repo_id (SEC-14)."""
    run = verify_verification_run_ownership(run_id=run_id, current_user=current_user, db=db)
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
    if not finding or finding.repo_id != repo_id:
        record_audit_event(
            db=db,
            action="CROSS_REPOSITORY_VERIFICATION_REFERENCE_BLOCKED",
            resource_type="verification_run",
            resource_identifier=run_id,
            actor_id=current_user.id,
            metadata={"target_repo_id": repo_id},
        )
        raise ForbiddenError("Referenced verification run does not belong to the specified repository.")
    if finding_id and run.finding_id != finding_id:
        raise ForbiddenError("Referenced verification run does not match the specified finding.")
    return run
