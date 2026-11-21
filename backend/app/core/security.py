from datetime import datetime, timedelta, timezone
import re
import time
from typing import Any, Dict, Optional
import uuid
import bcrypt
import jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from .config import settings
from .errors import SessionExpiredError, UnauthorizedError
from .logging import get_logger

logger = get_logger("redmercury.security")
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt with standard salt generation."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash in constant time."""
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception as e:
        logger.warning("Password verification failed due to format error")
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a cryptographically signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    if "jti" not in to_encode:
        to_encode["jti"] = str(uuid.uuid4())

    to_encode.update({
        "exp": expire,
        "iat": now,
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise SessionExpiredError("Session token has expired. Please sign in again.")
    except jwt.PyJWTError as e:
        raise UnauthorizedError("Invalid or corrupted authentication token.")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces essential AppSec HTTP headers on all outgoing responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Assign or propagate sanitized correlation Request ID (prevents header/log injection)
        incoming_id = (request.headers.get("X-Request-ID") or "").strip()
        request_id = incoming_id if _SAFE_REQUEST_ID_RE.match(incoming_id) else str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 2. Append standard AppSec response headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        if request.url.path.startswith("/api/v1/auth/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Log request completion with correlation info
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} ({duration_ms}ms)",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces maximum allowed request body size to prevent DoS attacks."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > settings.MAX_REQUEST_BODY_SIZE_BYTES:
                    from starlette.responses import JSONResponse
                    max_mb = settings.MAX_REQUEST_BODY_SIZE_BYTES // (1024 * 1024)
                    return JSONResponse(
                        status_code=413,
                        content={
                            "success": False,
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request payload exceeds maximum allowed size ({max_mb} MB).",
                            },
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)


class InMemoryRateLimiter:
    """Thread-safe sliding window rate limiter with bounded key capacity to prevent memory DoS."""

    def __init__(self, max_keys: int = 10000):
        import threading
        from collections import defaultdict, deque
        self._lock = threading.Lock()
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._max_keys = max_keys

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        import time
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            if len(self._requests) >= self._max_keys and key not in self._requests:
                stale_keys = [k for k, dq in self._requests.items() if not dq or dq[-1] < cutoff]
                for k in stale_keys:
                    del self._requests[k]
                if len(self._requests) >= self._max_keys:
                    oldest_key = min(self._requests.items(), key=lambda item: item[1][-1] if item[1] else 0)[0]
                    del self._requests[oldest_key]
            q = self._requests[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= max_requests:
                return False
            q.append(now)
            return True

    def reset(self):
        with self._lock:
            self._requests.clear()


auth_rate_limiter = InMemoryRateLimiter()


def get_client_ip(request: Request) -> str:
    """Safely extracts client IP address preventing X-Forwarded-For spoofing by untrusted clients."""
    peer_ip = request.client.host if request.client else "unknown"
    trusted_proxies = set(getattr(settings, "TRUSTED_PROXIES", ["127.0.0.1", "::1", "localhost", "testserver"]))

    # Only trust proxy headers when request arrives from a trusted proxy IP
    if peer_ip in trusted_proxies:
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()
        real_ip = request.headers.get("X-Real-IP")
        if real_ip and real_ip.strip():
            return real_ip.strip()
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            if parts:
                return parts[0]

    return peer_ip


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces rate limiting on authentication and expensive operational endpoints to prevent abuse and resource exhaustion."""

    AUTH_RATE_LIMITED_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/register",
    }

    INGEST_PATHS = {
        "/api/v1/repositories/ingest/upload",
        "/api/v1/repositories/ingest/git",
        "/api/v1/repositories/ingest/local",
    }

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path.rstrip("/")
        method = request.method.upper()
        client_ip = get_client_ip(request)

        # 1. Authentication Rate Limiting
        if settings.AUTH_RATE_LIMITING_ENABLED and method == "POST" and path in self.AUTH_RATE_LIMITED_PATHS:
            limiter_key = f"{path}:{client_ip}"
            allowed = auth_rate_limiter.is_allowed(
                key=limiter_key,
                max_requests=settings.AUTH_RATE_LIMIT_LOGIN_MAX,
                window_seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
            )

            if not allowed:
                from starlette.responses import JSONResponse
                logger.warning(
                    f"Authentication rate limit exceeded for IP {client_ip} on {path}",
                    extra={"ip": client_ip, "path": path},
                )
                return JSONResponse(
                    status_code=429,
                    headers={
                        "Retry-After": str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS),
                    },
                    content={
                        "success": False,
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "Too many authentication attempts. Please try again later.",
                        },
                    },
                )

        # 2. Operational Rate Limiting (Repository Ingestion, Scans, AI Requests, Reports)
        if getattr(settings, "OPERATION_RATE_LIMITING_ENABLED", True):
            op_category = None
            max_reqs = None
            window = getattr(settings, "OPERATION_RATE_LIMIT_WINDOW_SECONDS", 60)

            if method == "POST" and path in self.INGEST_PATHS:
                op_category = "repository ingestion"
                max_reqs = getattr(settings, "RATE_LIMIT_INGEST_MAX", 15)
            elif method == "POST" and path == "/api/v1/scans":
                op_category = "scan creation"
                max_reqs = getattr(settings, "RATE_LIMIT_SCAN_MAX", 20)
            elif method == "POST" and path == "/api/v1/analyze-finding":
                op_category = "AI security analysis"
                max_reqs = getattr(settings, "RATE_LIMIT_AI_MAX", 30)
            elif method == "GET" and (path.startswith("/api/v1/evidence/reports") or "/reports/" in path):
                op_category = "report generation"
                max_reqs = getattr(settings, "RATE_LIMIT_REPORTS_MAX", 30)

            if op_category and max_reqs:
                # Key by token hash if present to prevent IP-rotation bypass, otherwise fallback to IP
                caller = client_ip
                auth_hdr = request.headers.get("Authorization")
                cookie_tok = request.cookies.get(settings.COOKIE_NAME)
                tok = None
                if auth_hdr and auth_hdr.startswith("Bearer "):
                    tok = auth_hdr.split(" ", 1)[1].strip()
                elif cookie_tok:
                    tok = cookie_tok.strip()
                if tok:
                    import hashlib
                    caller = f"usr_{hashlib.sha256(tok.encode('utf-8')).hexdigest()[:12]}"

                limiter_key = f"op:{op_category}:{caller}"
                allowed = auth_rate_limiter.is_allowed(
                    key=limiter_key,
                    max_requests=max_reqs,
                    window_seconds=window,
                )

                if not allowed:
                    from starlette.responses import JSONResponse
                    logger.warning(
                        f"Operational rate limit exceeded for {caller} on {path} ({op_category})",
                        extra={"caller": caller, "path": path, "category": op_category},
                    )
                    return JSONResponse(
                        status_code=429,
                        headers={
                            "Retry-After": str(window),
                        },
                        content={
                            "success": False,
                            "error": {
                                "code": "RATE_LIMIT_EXCEEDED",
                                "message": f"Too many requests for {op_category}. Please try again later.",
                            },
                        },
                    )

        return await call_next(request)

