"""Authentication and session management API endpoints."""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import (
    VALID_ROLES,
    extract_token,
    generate_csrf_token,
    get_current_user,
    get_current_user_optional,
    issue_refresh_token_session,
    revoke_refresh_token_family,
    revoke_token,
    rotate_refresh_token_session,
    verify_csrf_origin,
)
from ....core.config import settings
from ....core.errors import AccountInactiveError, AppSecException, UnauthorizedError, ValidationError
from ....core.security import auth_rate_limiter, create_access_token, hash_password, verify_password
from ....db.session import get_db
from ....models.user import User
from ....schemas.auth import DEFAULT_REGISTERED_ROLE, LogoutResponse, TokenResponse, UserLogin, UserRead, UserRegister, UserRole

router = APIRouter()

# Constant-time dummy hash to equalize bcrypt execution time when email is not found
DUMMY_BCRYPT_HASH = "$2b$12$K1H1qS0rWd7E6zY0kQ2eDuYpZkZ6V9E4rI0E2f7Y5W4Q1A3V8K6e2"


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    expires_in_seconds: int,
) -> None:
    """Set HttpOnly access & refresh cookies plus double-submit CSRF cookie."""
    cookie_kwargs = {}
    if settings.COOKIE_DOMAIN:
        cookie_kwargs["domain"] = settings.COOKIE_DOMAIN

    refresh_max_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    csrf_token = generate_csrf_token()

    # 1. Short-lived HttpOnly access cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=expires_in_seconds,
        path="/",
        **cookie_kwargs,
    )
    # 2. Rotating HttpOnly refresh cookie scoped strictly to /api/v1/auth
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=refresh_max_age,
        path="/api/v1/auth",
        **cookie_kwargs,
    )
    # 3. Non-HttpOnly double-submit CSRF cookie (read by SPA and echoed in X-CSRF-Token)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=refresh_max_age,
        path="/",
        **cookie_kwargs,
    )


def _clear_auth_cookies(response: Response) -> None:
    """Clear access, refresh, and CSRF session cookies."""
    cookie_kwargs = {}
    if settings.COOKIE_DOMAIN:
        cookie_kwargs["domain"] = settings.COOKIE_DOMAIN

    response.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/",
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        **cookie_kwargs,
    )
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path="/api/v1/auth",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        **cookie_kwargs,
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        **cookie_kwargs,
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new security practitioner account",
)
def register(
    user_in: UserRegister,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # 1. Normalize and check uniqueness
    normalized_email = user_in.email.strip().lower()
    existing = db.query(User).filter(User.email == normalized_email).first()
    if existing:
        raise ValidationError("An account with this email address already exists.")

    # 2. Hash password with bcrypt
    hashed = hash_password(user_in.password)

    # 3. Create active user record with least-privileged default role (never admin via public registration)
    user = User(
        email=normalized_email,
        password_hash=hashed,
        account_status="active",
        role=DEFAULT_REGISTERED_ROLE.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 4. Generate short-lived access token & rotating refresh session
    access_token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_token, _ = issue_refresh_token_session(db=db, user_id=user.id)

    # 5. Set secure HTTP-only session cookies + CSRF cookie
    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=expires_in_seconds,
    )

    # 6. Record sanitized audit event
    record_audit_event(
        db=db,
        action="USER_REGISTRATION_SUCCESS",
        resource_type="user",
        resource_identifier=user.id,
        actor_id=user.id,
        metadata={"email": user.email},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate user and establish session",
)
def login(
    user_in: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    normalized_email = user_in.email.strip().lower()

    # 1. Block development seed account in production, staging, and desktop deployments
    if settings.is_dev_seed_blocked and normalized_email == "dev@xerova.com":
        record_audit_event(
            db=db,
            action="LOGIN_BLOCKED_DEV_SEED_IN_PRODUCTION",
            resource_type="auth",
            resource_identifier=None,
            actor_id=None,
            metadata={"email": normalized_email, "reason": "Seed account strictly prohibited in production/staging"},
        )
        raise UnauthorizedError("Invalid email or password.")

    # 2. Account-level rate limiting to prevent distributed brute-force attacks against target accounts
    account_key = f"auth_account:{normalized_email}"
    if not auth_rate_limiter.is_allowed(key=account_key, max_requests=10, window_seconds=60):
        record_audit_event(
            db=db,
            action="LOGIN_RATE_LIMITED_ACCOUNT",
            resource_type="auth",
            resource_identifier=None,
            actor_id=None,
            metadata={"email": normalized_email},
        )
        raise AppSecException(
            message="Too many authentication attempts for this account. Please wait a minute and try again.",
            code="RATE_LIMIT_EXCEEDED",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    user = db.query(User).filter(User.email == normalized_email).first()

    # 3. Constant-time check: equalize response time whether email exists or not
    if not user:
        verify_password(user_in.password, DUMMY_BCRYPT_HASH)
        record_audit_event(
            db=db,
            action="LOGIN_FAILED_CREDENTIALS",
            resource_type="auth",
            resource_identifier=None,
            actor_id=None,
            metadata={"email": normalized_email},
        )
        raise UnauthorizedError("Invalid email or password.")

    if not verify_password(user_in.password, user.password_hash):
        record_audit_event(
            db=db,
            action="LOGIN_FAILED_CREDENTIALS",
            resource_type="auth",
            resource_identifier=None,
            actor_id=user.id,
            metadata={"email": normalized_email},
        )
        raise UnauthorizedError("Invalid email or password.")

    if user.account_status != "active":
        record_audit_event(
            db=db,
            action="LOGIN_BLOCKED_INACTIVE_ACCOUNT",
            resource_type="user",
            resource_identifier=user.id,
            actor_id=user.id,
            metadata={"status": user.account_status},
        )
        raise AccountInactiveError("This account is currently inactive or suspended.")

    effective_role = (user.role or "").strip().lower()
    if effective_role not in VALID_ROLES:
        effective_role = UserRole.VIEWER.value
    access_token = create_access_token({"sub": user.id, "email": user.email, "role": effective_role})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_token, _ = issue_refresh_token_session(db=db, user_id=user.id)

    # Set secure HTTP-only session cookies + CSRF cookie
    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=expires_in_seconds,
    )

    record_audit_event(
        db=db,
        action="USER_LOGIN_SUCCESS",
        resource_type="user",
        resource_identifier=user.id,
        actor_id=user.id,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate HttpOnly refresh token and issue a fresh short-lived access token",
)
def refresh_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # Enforce CSRF origin + double-submit token validation on cookie-backed refresh
    verify_csrf_origin(request, force_cookie_check=True)

    raw_refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not raw_refresh:
        _clear_auth_cookies(response)
        raise UnauthorizedError("Refresh token cookie is missing. Please sign in again.")

    try:
        user, new_refresh_token, new_session = rotate_refresh_token_session(
            db=db,
            raw_refresh_token=raw_refresh,
        )
    except Exception:
        _clear_auth_cookies(response)
        raise

    effective_role = (user.role or UserRole.VIEWER.value).strip().lower()
    access_token = create_access_token({"sub": user.id, "email": user.email, "role": effective_role})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    _set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in_seconds=expires_in_seconds,
    )

    record_audit_event(
        db=db,
        action="SESSION_TOKEN_ROTATED",
        resource_type="auth_session",
        resource_identifier=new_session.family_id,
        actor_id=user.id,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=expires_in_seconds,
        user=UserRead.model_validate(user),
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Clear session credentials, revoke active tokens, and invalidate refresh family",
)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    # Enforce CSRF protection when logout is authenticated via cookies
    verify_csrf_origin(request)

    token = extract_token(request)
    if token:
        revoke_token(db=db, token=token, reason="logout")

    raw_refresh = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if raw_refresh:
        revoke_refresh_token_family(db=db, raw_refresh_token=raw_refresh, reason="logout")

    _clear_auth_cookies(response)

    if current_user:
        record_audit_event(
            db=db,
            action="USER_LOGOUT",
            resource_type="user",
            resource_identifier=current_user.id,
            actor_id=current_user.id,
        )

    return LogoutResponse(success=True, message="Successfully logged out.")


@router.get(
    "/me",
    response_model=UserRead,
    summary="Get authenticated user profile and session state",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserRead:
    return UserRead.model_validate(current_user)
