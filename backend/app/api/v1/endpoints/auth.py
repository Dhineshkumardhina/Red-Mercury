"""Authentication and session management API endpoints."""
from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import extract_token, get_current_user, get_current_user_optional, revoke_token
from ....core.config import settings
from ....core.errors import AccountInactiveError, AppSecException, UnauthorizedError, ValidationError
from ....core.security import auth_rate_limiter, create_access_token, hash_password, verify_password
from ....db.session import get_db
from ....models.user import User
from ....schemas.auth import LogoutResponse, TokenResponse, UserLogin, UserRead, UserRegister

router = APIRouter()

# Constant-time dummy hash to equalize bcrypt execution time when email is not found
DUMMY_BCRYPT_HASH = "$2b$12$K1H1qS0rWd7E6zY0kQ2eDuYpZkZ6V9E4rI0E2f7Y5W4Q1A3V8K6e2"


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

    # 3. Create active user record
    user = User(
        email=normalized_email,
        password_hash=hashed,
        account_status="active",
        role=user_in.role or "admin",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 4. Generate JWT access token
    access_token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # 5. Set secure HTTP-only session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=expires_in_seconds,
        path="/",
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

    # 1. Block development seed account in production deployments
    if settings.is_production and normalized_email == "dev@xerova.com":
        record_audit_event(
            db=db,
            action="LOGIN_BLOCKED_DEV_SEED_IN_PRODUCTION",
            resource_type="auth",
            resource_identifier=None,
            actor_id=None,
            metadata={"email": normalized_email, "reason": "Seed account strictly prohibited in production"},
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

    access_token = create_access_token({"sub": user.id, "email": user.email, "role": user.role or "admin"})
    expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Set secure HTTP-only session cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=access_token,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
        max_age=expires_in_seconds,
        path="/",
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
    "/logout",
    response_model=LogoutResponse,
    summary="Clear session credentials and log out",
)
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user_optional),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    token = extract_token(request)
    if token:
        revoke_token(db=db, token=token, reason="logout")

    response.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/",
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.cookie_secure,
        samesite=settings.COOKIE_SAMESITE,
    )

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
