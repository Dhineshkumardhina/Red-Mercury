from typing import List, Optional, Union
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Core Application Metadata
    APP_NAME: str = "Red Mercury"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"  # development, staging, production
    DEBUG: bool = False
    ORGANIZATION: str = "Xerova Digital Solutions"

    # API Routing
    API_V1_PREFIX: str = "/api/v1"

    # Server Host & Port (Default to localhost; set HOST=0.0.0.0 in container deployments)
    HOST: str = "127.0.0.1"
    PORT: int = 8001

    # Database Configuration (SQLite default for local dev, PostgreSQL for production)
    DATABASE_URL: str = "sqlite:///./redmercury.db"

    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "null",
    ]

    # Trusted Hosts & Reverse-Proxy Settings
    ALLOWED_HOSTS: Union[List[str], str] = [
        "redmercury.xerova.com",
        "red-mercury.dhineshkumardhina18.workers.dev",
        "localhost",
        "127.0.0.1",
        "testserver",
    ]
    TRUSTED_PROXIES: List[str] = [
        "127.0.0.1",
        "::1",
        "localhost",
        "testserver",
    ]

    # CSRF Defense Configuration
    CSRF_PROTECTION_ENABLED: bool = True

    # Structured Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT_JSON: bool = False

    # Security Secret & Cryptography (Must be overridden in production/staging)
    SECRET_KEY: str = "dev-insecure-secret-key-32-chars-long!!"
    ENCRYPTION_KEY: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Short-lived access tokens (rotated via HttpOnly refresh cookie)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # GitHub Webhook Signature Secret (Dedicated HMAC secret; distinct from SECRET_KEY)
    GITHUB_WEBHOOK_SECRET: Optional[str] = None

    # Development-only seed credentials (Used exclusively in local development seed scripts)
    DEV_SEED_PASSWORD: str = "XerovaDevPass2026!"

    # Distributed Rate Limiting (Redis in multi-instance staging/production; in-memory fallback in local dev)
    REDIS_URL: Optional[str] = None
    RATE_LIMIT_FAIL_OPEN: bool = True  # Set False in strict deployments to fail closed on Redis outage

    # Authentication Rate Limiting (distinct per-endpoint limits)
    AUTH_RATE_LIMITING_ENABLED: bool = True
    AUTH_RATE_LIMIT_LOGIN_MAX: int = 10  # Max login attempts per window per IP
    AUTH_RATE_LIMIT_REGISTER_MAX: int = 5  # Max registration attempts per window per IP
    AUTH_RATE_LIMIT_REFRESH_MAX: int = 30  # Max refresh attempts per window per IP
    AUTH_RATE_LIMIT_LOGOUT_MAX: int = 20  # Max logout attempts per window per IP
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60  # Sliding window duration in seconds

    # Operational & Expensive Endpoint Rate Limiting
    OPERATION_RATE_LIMITING_ENABLED: bool = True
    RATE_LIMIT_INGEST_MAX: int = 15  # Max repo ingestion requests per window
    RATE_LIMIT_SCAN_MAX: int = 20  # Max scan creation requests per window
    RATE_LIMIT_VERIFICATION_MAX: int = 15  # Max fix-verification requests per window
    RATE_LIMIT_VALIDATION_MAX: int = 25  # Max AI validation requests per window
    RATE_LIMIT_AI_MAX: int = 30  # Max AI analysis requests per window
    RATE_LIMIT_WEBHOOK_MAX: int = 60  # Max GitHub webhook deliveries per window per IP
    RATE_LIMIT_REPORTS_MAX: int = 30  # Max report generation/download requests per window
    OPERATION_RATE_LIMIT_WINDOW_SECONDS: int = 60  # Sliding window duration in seconds

    # Cookie Session Configuration
    COOKIE_NAME: str = "access_token"
    REFRESH_COOKIE_NAME: str = "refresh_token"
    CSRF_COOKIE_NAME: str = "rm_csrf_token"
    COOKIE_DOMAIN: Optional[str] = None
    COOKIE_SAMESITE: str = "lax"  # "lax", "strict", or "none" (with Secure=True for cross-site)
    COOKIE_HTTPONLY: bool = True

    # AI Security Analyst & Offline Engine Configuration
    OFFLINE_MODE: bool = True  # Fully offline execution: disables external network calls
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    AI_TIMEOUT_SECONDS: int = 15
    AI_MAX_RETRIES: int = 2


    # Repository Ingestion & Workspace Hardening Settings
    WORKSPACE_ROOT: str = "data/workspaces"
    ALLOW_LOCAL_INGESTION_IN_PRODUCTION: bool = False
    LOCAL_INGESTION_ALLOWED_ROOTS: Union[List[str], str] = []
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB max zip upload
    MAX_EXTRACTED_SIZE_BYTES: int = 200 * 1024 * 1024  # 200 MB max uncompressed expansion
    MAX_FILE_COUNT: int = 5000  # Max files allowed in archive
    MAX_COMPRESSION_RATIO: float = 100.0  # Zip bomb detection threshold
    MAX_SINGLE_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB per file limit
    MAX_NESTED_ARCHIVES: int = 5  # Max nested archive entries permitted in an upload
    GIT_CLONE_TIMEOUT_SECONDS: int = 60  # Git clone timeout
    ALLOW_PRIVATE_NETWORKS: bool = False  # SSRF protection: block private/cloud IPs
    GIT_EGRESS_PROXY_URL: Optional[str] = None  # Mandatory in strict envs to enable public Git ingestion
    ALLOW_PRIVATE_GIT_EGRESS_PROXY: bool = False  # Only True when routing to an approved internal proxy container
    APPROVED_GIT_EGRESS_PROXY_HOSTS: Union[List[str], str] = ["egress-proxy", "smokescreen"]
    GITLEAKS_VERSION: str = "8.18.2"
    GITLEAKS_LINUX_X64_SHA256: str = "6298c9235dfc9278c14b28afd9b7fa4e6f4a289cb1974bd27949fc1e9122bdee"

    # Operational Safety & Concurrency Limits
    DOCS_ENABLED: bool = True
    MAX_CONCURRENT_SCANS_PER_USER: int = 3
    MAX_DAILY_SCANS_PER_USER: int = 100
    MAX_CONCURRENT_VERIFICATIONS_PER_USER: int = 3
    MAX_REQUEST_BODY_SIZE_BYTES: int = 60 * 1024 * 1024  # 60 MB maximum raw HTTP request body
    STALE_JOB_TIMEOUT_MINUTES: int = 15

    # Phase 6: Durable Job Execution, Lease, Heartbeat & Retry Settings
    JOB_DISPATCH_MODE: str = "auto"  # "queue_only" (always enforced in strict_env) or "auto"
    JOB_QUEUE_NAME: str = "redmercury:jobs:queue"
    JOB_LEASE_DURATION_SECONDS: int = 60
    JOB_HEARTBEAT_INTERVAL_SECONDS: int = 15
    JOB_MAX_ATTEMPTS: int = 3
    JOB_RETRY_BASE_DELAY_SECONDS: float = 2.0
    JOB_RETRY_MAX_DELAY_SECONDS: float = 60.0
    WORKER_CONCURRENCY: int = 2
    WORKER_POLL_INTERVAL_SECONDS: float = 2.0

    # Verification Sandbox & Isolation Settings
    SANDBOX_BACKEND: str = "docker"  # "docker", "auto", "restricted_subprocess"
    SANDBOX_FAIL_CLOSED: bool = True
    SANDBOX_ALLOW_HOST_FALLBACK: bool = False
    SANDBOX_CONTAINER_IMAGE: str = "redmercury-worker:latest"
    SANDBOX_USER: str = "10002:10002"
    SANDBOX_MEMORY_LIMIT: str = "512m"
    SANDBOX_CPU_LIMIT: str = "1.0"
    SANDBOX_PIDS_LIMIT: int = 50
    SANDBOX_NETWORK_ISOLATION: bool = True
    SANDBOX_READ_ONLY_ROOT: bool = True

    @property
    def sandbox_allow_host_fallback(self) -> bool:
        """Never allow host fallback in production or staging, even if configured."""
        if self.is_strict_env:
            return False
        return self.SANDBOX_ALLOW_HOST_FALLBACK

    @property
    def cookie_secure(self) -> bool:
        """Enforce HTTPS cookie secure flag in production and staging."""
        return self.is_strict_env

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        if isinstance(v, str):
            if v.startswith("postgres://"):
                return "postgresql+psycopg://" + v[len("postgres://"):]
            if v.startswith("postgresql://"):
                return "postgresql+psycopg://" + v[len("postgresql://"):]
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def assemble_allowed_hosts(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    @field_validator("LOCAL_INGESTION_ALLOWED_ROOTS", mode="before")
    @classmethod
    def assemble_local_ingestion_allowed_roots(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if not v.strip():
                return []
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return [str(item).strip() for item in v if str(item).strip()]
        return []

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def is_staging(self) -> bool:
        return self.APP_ENV.lower() == "staging"

    @property
    def is_strict_env(self) -> bool:
        """True for both production and staging — enforces identical security gates (SEC-17)."""
        return self.APP_ENV.lower() in ("production", "staging")

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        """Strict production & staging configuration validator to prevent silent insecure defaults."""
        import os
        railway_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
        if isinstance(self.ALLOWED_HOSTS, list):
            if railway_domain and railway_domain not in self.ALLOWED_HOSTS:
                self.ALLOWED_HOSTS.append(railway_domain)
            if os.getenv("RAILWAY_ENVIRONMENT") and "healthcheck.railway.app" not in self.ALLOWED_HOSTS:
                self.ALLOWED_HOSTS.append("healthcheck.railway.app")

        if self.is_strict_env:
            env_label = self.APP_ENV.lower()
            # 1. Cryptographic Secret Key Security
            if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    f"Deployment ({env_label}) requires a cryptographically strong SECRET_KEY (minimum 32 characters, no development defaults)."
                )
            if "dev-insecure" in self.SECRET_KEY or "replace-in-production" in self.SECRET_KEY:
                raise ValueError(
                    f"Deployment ({env_label}) requires a cryptographically strong SECRET_KEY (minimum 32 characters, no development defaults)."
                )

            # 2. Database Backend Safety
            if self.DATABASE_URL.startswith("sqlite"):
                raise ValueError(
                    f"SQLite cannot be used in {env_label}. Configure a PostgreSQL DATABASE_URL."
                )

            # 3. CORS Origins Lockdown
            origins = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [self.CORS_ORIGINS]
            if "*" in origins:
                raise ValueError(
                    f"Wildcard '*' in CORS_ORIGINS is strictly prohibited in {env_label}."
                )
            if any(o.strip().lower() == "null" for o in origins):
                raise ValueError(
                    f"The 'null' origin in CORS_ORIGINS is strictly prohibited in {env_label}."
                )

            # 4. SSRF Private Network Access Lockdown
            if self.ALLOW_PRIVATE_NETWORKS:
                raise ValueError(
                    f"ALLOW_PRIVATE_NETWORKS must be False in {env_label} to protect internal network services."
                )

            # 5. Allowed Hosts Lockdown
            hosts = self.ALLOWED_HOSTS if isinstance(self.ALLOWED_HOSTS, list) else [self.ALLOWED_HOSTS]
            if "*" in hosts:
                raise ValueError(
                    f"Wildcard '*' in ALLOWED_HOSTS is strictly prohibited in {env_label}."
                )

            # 6. Debug Mode Lockdown
            if self.DEBUG:
                raise ValueError(
                    f"DEBUG mode must be False in {env_label} deployments to prevent stack trace disclosure."
                )

            # 7. CSRF & Rate Limiting Enforcement
            if not self.CSRF_PROTECTION_ENABLED:
                raise ValueError(
                    f"CSRF_PROTECTION_ENABLED must be True in {env_label} deployments."
                )
            if not self.AUTH_RATE_LIMITING_ENABLED:
                raise ValueError(
                    f"AUTH_RATE_LIMITING_ENABLED must be True in {env_label} deployments."
                )

            # 8. Local Filesystem Ingestion Lockdown
            if self.ALLOW_LOCAL_INGESTION_IN_PRODUCTION:
                allowed_roots = (
                    self.LOCAL_INGESTION_ALLOWED_ROOTS
                    if isinstance(self.LOCAL_INGESTION_ALLOWED_ROOTS, list)
                    else [self.LOCAL_INGESTION_ALLOWED_ROOTS]
                )
                if not [r for r in allowed_roots if str(r).strip()]:
                    raise ValueError(
                        "ALLOW_LOCAL_INGESTION_IN_PRODUCTION requires non-empty LOCAL_INGESTION_ALLOWED_ROOTS."
                    )

            # 9. Cookie SameSite validation
            samesite_val = (self.COOKIE_SAMESITE or "").strip().lower()
            if samesite_val not in ("lax", "strict", "none"):
                raise ValueError(
                    f"Invalid COOKIE_SAMESITE '{self.COOKIE_SAMESITE}'. Must be 'lax', 'strict', or 'none'."
                )

            # 10. Sandbox fail-closed parity
            if not self.SANDBOX_FAIL_CLOSED:
                raise ValueError(
                    f"SANDBOX_FAIL_CLOSED must be True in {env_label} deployments."
                )

        return self


settings = Settings()
