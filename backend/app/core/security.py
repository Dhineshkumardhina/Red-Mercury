from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import posixpath
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple
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
JWT_ISSUER = "red-mercury"


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
    except Exception:
        logger.warning("Password verification failed due to format error")
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a cryptographically signed short-lived JWT access token."""
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
        "iss": JWT_ISSUER,
        "typ": "access",
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
        token_type = payload.get("typ")
        if token_type is not None and token_type != "access":
            raise UnauthorizedError("Invalid authentication token type.")
        issuer = payload.get("iss")
        if issuer is not None and issuer != JWT_ISSUER:
            raise UnauthorizedError("Invalid authentication token issuer.")
        return payload
    except jwt.ExpiredSignatureError:
        raise SessionExpiredError("Session token has expired. Please sign in again.")
    except UnauthorizedError:
        raise
    except jwt.PyJWTError:
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

        if settings.is_strict_env:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        ipc_token = (getattr(settings, "REDMERCURY_IPC_TOKEN", None) or "").strip()
        if ipc_token and request.url.path.rstrip("/") == f"{settings.API_V1_PREFIX}/health":
            req_ipc = (request.headers.get("X-RedMercury-IPC-Token") or "").strip()
            if req_ipc and hmac.compare_digest(ipc_token, req_ipc):
                response.headers["X-RedMercury-IPC-Verified"] = "true"

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


class _RequestBodyTooLargeError(Exception):
    """Internal sentinel raised when streaming request body bytes exceed MAX_REQUEST_BODY_SIZE_BYTES."""


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforces maximum allowed request body size across both Content-Length and chunked streams (Task 7 / SEC-19)."""

    @staticmethod
    def _payload_too_large_response(max_bytes: int):
        from starlette.responses import JSONResponse
        max_mb = max(1, max_bytes // (1024 * 1024)) if max_bytes >= (1024 * 1024) else max_bytes
        unit = "MB" if max_bytes >= (1024 * 1024) else "bytes"
        return JSONResponse(
            status_code=413,
            content={
                "success": False,
                "error": {
                    "code": "PAYLOAD_TOO_LARGE",
                    "message": f"Request payload exceeds maximum allowed size ({max_mb} {unit}).",
                },
            },
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        max_bytes = int(getattr(settings, "MAX_REQUEST_BODY_SIZE_BYTES", 60 * 1024 * 1024))

        # 1. Fast-path Content-Length header validation
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length.strip())
                if length < 0:
                    from starlette.responses import JSONResponse
                    return JSONResponse(
                        status_code=400,
                        content={
                            "success": False,
                            "error": {
                                "code": "BAD_REQUEST",
                                "message": "Invalid negative Content-Length header.",
                            },
                        },
                    )
                if length > max_bytes:
                    return self._payload_too_large_response(max_bytes)
            except ValueError:
                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=400,
                    content={
                        "success": False,
                        "error": {
                            "code": "BAD_REQUEST",
                            "message": "Malformed Content-Length header.",
                        },
                    },
                )

        # 2. Streaming chunked / missing-Content-Length body byte counter
        bytes_received = 0
        original_receive = request._receive

        async def _bounded_receive():
            nonlocal bytes_received
            message = await original_receive()
            msg_type = message.get("type")
            if msg_type == "http.disconnect":
                return message
            if msg_type == "http.request":
                body_chunk = message.get("body", b"") or b""
                bytes_received += len(body_chunk)
                if bytes_received > max_bytes:
                    raise _RequestBodyTooLargeError()
            return message

        request._receive = _bounded_receive

        try:
            return await call_next(request)
        except Exception as exc:
            # Unwrap ExceptionGroup / BaseHTTPMiddleware wrapped exceptions if _RequestBodyTooLargeError was raised
            if isinstance(exc, _RequestBodyTooLargeError) or "_RequestBodyTooLargeError" in repr(exc):
                return self._payload_too_large_response(max_bytes)
            cause = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
            if isinstance(cause, _RequestBodyTooLargeError):
                return self._payload_too_large_response(max_bytes)
            raise


# Atomic sliding-window Lua script for Redis distributed rate limiting
_REDIS_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now_ms - window_ms)
local count = redis.call('ZCARD', key)
if count >= max_requests then
    return 0
end
redis.call('ZADD', key, now_ms, member)
redis.call('PEXPIRE', key, window_ms + 1000)
return 1
"""


class InMemoryRateLimiter:
    """Thread-safe sliding window rate limiter with bounded key capacity to prevent memory DoS."""

    def __init__(self, max_keys: int = 10000):
        self._lock = threading.Lock()
        self._requests: Dict[str, deque] = defaultdict(deque)
        self._max_keys = max_keys

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
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


class RedisRateLimiter:
    """Atomic Redis sliding-window rate limiter safe across multiple concurrent API instances."""

    def __init__(self, redis_client: Any, key_prefix: str = "rm:rl:"):
        self._client = redis_client
        self._key_prefix = key_prefix

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        now_ms = int(time.time() * 1000)
        window_ms = int(window_seconds * 1000)
        member = f"{now_ms}:{uuid.uuid4().hex}"
        full_key = f"{self._key_prefix}{key}"
        result = self._client.eval(
            _REDIS_SLIDING_WINDOW_LUA,
            1,
            full_key,
            now_ms,
            window_ms,
            int(max_requests),
            member,
        )
        return int(result) == 1

    def reset(self):
        if hasattr(self._client, "flushdb"):
            self._client.flushdb()


class DistributedRateLimiter:
    """Facade combining Redis-backed distributed limiting with safe outage handling & in-memory fallback."""

    def __init__(self):
        self._fallback = InMemoryRateLimiter()
        self._redis_limiter: Optional[RedisRateLimiter] = None
        self._initialized_url: Optional[str] = None
        self._lock = threading.Lock()

    def configure_redis(self, redis_client: Optional[Any]) -> None:
        """Inject a Redis client explicitly (used for testing or custom pools)."""
        with self._lock:
            if redis_client is None:
                self._redis_limiter = None
                self._initialized_url = None
            else:
                self._redis_limiter = RedisRateLimiter(redis_client)
                self._initialized_url = "__injected__"

    def _ensure_redis_backend(self) -> Optional[RedisRateLimiter]:
        redis_url = (getattr(settings, "REDIS_URL", None) or "").strip()
        if not redis_url:
            if self._initialized_url != "__injected__":
                return None
            return self._redis_limiter

        if self._redis_limiter is not None and self._initialized_url in (redis_url, "__injected__"):
            return self._redis_limiter

        with self._lock:
            if self._redis_limiter is not None and self._initialized_url in (redis_url, "__injected__"):
                return self._redis_limiter
            try:
                import redis  # type: ignore
                client = redis.Redis.from_url(
                    redis_url,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                    decode_responses=True,
                )
                self._redis_limiter = RedisRateLimiter(client)
                self._initialized_url = redis_url
            except Exception as exc:
                logger.warning(f"Failed to initialize Redis rate limiter ({redis_url}): {exc}")
                self._redis_limiter = None
        return self._redis_limiter

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> bool:
        redis_backend = self._ensure_redis_backend()
        if redis_backend is not None:
            try:
                return redis_backend.is_allowed(key, max_requests, window_seconds)
            except Exception as exc:
                logger.warning(f"Redis rate limiter error for key '{key}': {exc}")
                if not getattr(settings, "RATE_LIMIT_FAIL_OPEN", True):
                    return False
                # Fail-open fallback to local sliding window when configured
                return self._fallback.is_allowed(key, max_requests, window_seconds)

        # If REDIS_URL is configured but client failed to initialize and fail-closed is requested
        if (getattr(settings, "REDIS_URL", None) or "").strip() and not getattr(settings, "RATE_LIMIT_FAIL_OPEN", True):
            return False

        return self._fallback.is_allowed(key, max_requests, window_seconds)

    def reset(self):
        self._fallback.reset()
        if self._redis_limiter is not None:
            try:
                self._redis_limiter.reset()
            except Exception:
                pass


auth_rate_limiter = DistributedRateLimiter()


def _is_trusted_proxy_ip(candidate: str, trusted_entries: List[str]) -> bool:
    """Return True if candidate matches an exact trusted proxy name/IP or CIDR subnet."""
    cleaned = (candidate or "").strip()
    if not cleaned:
        return False
    for entry in trusted_entries:
        item = (entry or "").strip()
        if not item:
            continue
        if cleaned.lower() == item.lower():
            return True
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            if "/" in item:
                if ip_obj in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if ip_obj == ipaddress.ip_address(item):
                    return True
        except ValueError:
            continue
    return False


def get_client_ip(request: Request) -> str:
    """Extract the true client IP using rightmost-untrusted X-Forwarded-For parsing.

    - Ignores all proxy headers unless the direct peer IP is in TRUSTED_PROXIES (exact IP or CIDR).
    - Parses X-Forwarded-For from right to left, skipping trusted proxy hops, and returns the
      rightmost untrusted IP so attackers cannot spoof leftmost X-Forwarded-For entries.
    """
    peer_ip = request.client.host if request.client else "unknown"
    trusted_proxies = list(getattr(settings, "TRUSTED_PROXIES", ["127.0.0.1", "::1", "localhost", "testserver"]))

    if not _is_trusted_proxy_ip(peer_ip, trusted_proxies):
        return peer_ip

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        # Walk right-to-left: return the rightmost IP that is NOT a trusted proxy
        for hop in reversed(parts):
            if not _is_trusted_proxy_ip(hop, trusted_proxies):
                return hop
        if parts:
            return parts[0]

    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip and real_ip.strip():
        return real_ip.strip()

    return peer_ip


def _normalize_rate_limit_path(raw_path: str) -> str:
    """Canonicalize URL path to prevent rate-limit bypasses via '//', '/./', or trailing slashes."""
    normalized = posixpath.normpath(raw_path or "/")
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized.rstrip("/").lower() or "/"


class AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """Enforces distributed per-endpoint rate limiting on authentication and expensive endpoints."""

    INGEST_PATHS = {
        "/api/v1/repositories/ingest/upload",
        "/api/v1/repositories/ingest/git",
        "/api/v1/repositories/ingest/local",
    }

    def _resolve_auth_policy(self, method: str, norm_path: str) -> Optional[Tuple[str, int]]:
        if method != "POST":
            return None
        if norm_path == "/api/v1/auth/login":
            return "/api/v1/auth/login", getattr(settings, "AUTH_RATE_LIMIT_LOGIN_MAX", 10)
        if norm_path == "/api/v1/auth/register":
            return "/api/v1/auth/register", getattr(settings, "AUTH_RATE_LIMIT_REGISTER_MAX", 5)
        if norm_path == "/api/v1/auth/refresh":
            return "/api/v1/auth/refresh", getattr(settings, "AUTH_RATE_LIMIT_REFRESH_MAX", 30)
        if norm_path == "/api/v1/auth/logout":
            return "/api/v1/auth/logout", getattr(settings, "AUTH_RATE_LIMIT_LOGOUT_MAX", 20)
        return None

    def _resolve_operation_policy(self, method: str, norm_path: str) -> Optional[Tuple[str, int]]:
        if method == "POST" and norm_path in self.INGEST_PATHS:
            return "repository ingestion", getattr(settings, "RATE_LIMIT_INGEST_MAX", 15)
        if method == "POST" and norm_path == "/api/v1/scans":
            return "scan creation", getattr(settings, "RATE_LIMIT_SCAN_MAX", 20)
        if method == "POST" and norm_path == "/api/v1/verifications":
            return "fix verification", getattr(settings, "RATE_LIMIT_VERIFICATION_MAX", 15)
        if method == "POST" and norm_path.startswith("/api/v1/findings/") and norm_path.endswith("/validate"):
            return "AI vulnerability validation", getattr(settings, "RATE_LIMIT_VALIDATION_MAX", 25)
        if method == "POST" and norm_path == "/api/v1/analyze-finding":
            return "AI security analysis", getattr(settings, "RATE_LIMIT_AI_MAX", 30)
        if method == "POST" and norm_path == "/api/v1/integrations/github/webhook":
            return "GitHub webhook", getattr(settings, "RATE_LIMIT_WEBHOOK_MAX", 60)
        if method == "GET" and (norm_path.startswith("/api/v1/evidence/reports") or "/reports/" in norm_path):
            return "report generation", getattr(settings, "RATE_LIMIT_REPORTS_MAX", 30)
        return None

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        norm_path = _normalize_rate_limit_path(request.url.path)
        method = request.method.upper()
        client_ip = get_client_ip(request)

        # 1. Authentication Rate Limiting (distinct per-endpoint limits)
        if settings.AUTH_RATE_LIMITING_ENABLED:
            auth_policy = self._resolve_auth_policy(method, norm_path)
            if auth_policy is not None:
                canonical_route, max_reqs = auth_policy
                limiter_key = f"{canonical_route}:{client_ip}"
                allowed = auth_rate_limiter.is_allowed(
                    key=limiter_key,
                    max_requests=max_reqs,
                    window_seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
                )

                if not allowed:
                    from starlette.responses import JSONResponse
                    logger.warning(
                        f"Authentication rate limit exceeded for IP {client_ip} on {canonical_route}",
                        extra={"ip": client_ip, "path": canonical_route},
                    )
                    return JSONResponse(
                        status_code=429,
                        headers={"Retry-After": str(settings.AUTH_RATE_LIMIT_WINDOW_SECONDS)},
                        content={
                            "success": False,
                            "error": {
                                "code": "RATE_LIMIT_EXCEEDED",
                                "message": "Too many authentication attempts. Please try again later.",
                            },
                        },
                    )

        # 2. Operational Rate Limiting (Ingestion, Scans, Verifications, Validation, AI, Webhooks, Reports)
        if getattr(settings, "OPERATION_RATE_LIMITING_ENABLED", True):
            op_policy = self._resolve_operation_policy(method, norm_path)
            if op_policy is not None:
                op_category, max_reqs = op_policy
                window = getattr(settings, "OPERATION_RATE_LIMIT_WINDOW_SECONDS", 60)

                caller = client_ip
                auth_hdr = request.headers.get("Authorization")
                cookie_tok = request.cookies.get(settings.COOKIE_NAME)
                tok = None
                if auth_hdr and auth_hdr.startswith("Bearer "):
                    tok = auth_hdr.split(" ", 1)[1].strip()
                elif cookie_tok:
                    tok = cookie_tok.strip()
                if tok:
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
                        f"Operational rate limit exceeded for {caller} on {norm_path} ({op_category})",
                        extra={"caller": caller, "path": norm_path, "category": op_category},
                    )
                    return JSONResponse(
                        status_code=429,
                        headers={"Retry-After": str(window)},
                        content={
                            "success": False,
                            "error": {
                                "code": "RATE_LIMIT_EXCEEDED",
                                "message": f"Too many requests for {op_category}. Please try again later.",
                            },
                        },
                    )

        return await call_next(request)

