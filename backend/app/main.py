"""FastAPI application bootstrap for Red Mercury."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api.v1.router import api_v1_router
from .core.config import settings
from .core.errors import (
    AppSecException,
    appsec_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from .core.logging import get_logger, setup_logging
from .core.security import AuthRateLimitMiddleware, RequestSizeLimitMiddleware, SecurityHeadersMiddleware
from .db.base import Base
from .db.session import engine, SessionLocal
from .models.user import User
from .models.repository import Repository
from .models.finding import SecurityFinding
from .models.verification import VerificationRun

# Initialize structured logging
setup_logging(level=settings.LOG_LEVEL, json_format=settings.LOG_FORMAT_JSON)
logger = get_logger("redmercury.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle management."""
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}] "
        f"for {settings.ORGANIZATION}"
    )

    # In local development with SQLite, ensure tables exist
    if settings.is_sqlite:
        logger.info("Verifying local SQLite database schema...")
        Base.metadata.create_all(bind=engine)
        try:
            import os
            import sqlalchemy as sa
            from alembic import command
            from alembic.config import Config
            ini_candidates = [
                "backend/alembic.ini",
                "alembic.ini",
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend", "alembic.ini")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "alembic.ini")),
            ]
            ini_path = next((p for p in ini_candidates if os.path.exists(p)), None)
            if ini_path:
                cfg = Config(ini_path)
                has_alembic = False
                current_rev = None
                with engine.connect() as conn:
                    inspector = sa.inspect(conn)
                    has_alembic = "alembic_version" in inspector.get_table_names()
                    if has_alembic:
                        row = conn.execute(sa.text("SELECT version_num FROM alembic_version")).fetchone()
                        current_rev = row[0] if row else None

                HEAD_REVISION = "0014_add_durable_jobs_and_outbox"
                if has_alembic and current_rev != HEAD_REVISION:
                    command.upgrade(cfg, "head")
                elif not has_alembic:
                    command.stamp(cfg, "head")
        except Exception as exc:
            logger.warning(f"Database schema auto-migration check skipped: {exc}")

    # Reconcile any expired worker leases, undispatched outbox events, or legacy interrupted jobs on startup
    try:
        reconcile_db = SessionLocal()
        from .core.jobs import reconcile_jobs_on_startup
        reconcile_jobs_on_startup(reconcile_db, component="api")
        reconcile_db.close()
    except Exception as exc:
        logger.warning(f"Failed to reconcile durable jobs on startup: {exc}")

    yield

    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_application() -> FastAPI:
    """FastAPI application factory."""
    docs_url = "/docs" if (settings.DOCS_ENABLED and not settings.is_strict_env) else None
    redoc_url = "/redoc" if (settings.DOCS_ENABLED and not settings.is_strict_env) else None
    openapi_url = f"{settings.API_V1_PREFIX}/openapi.json" if (settings.DOCS_ENABLED and not settings.is_strict_env) else None

    app = FastAPI(
        title=f"{settings.APP_NAME} API",
        description="Application Security & Automated Fix Verification Engine by Xerova Digital Solutions.",
        version=settings.APP_VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # 0. Trusted Host Header Validation (Guards against Host header injection / cache poisoning)
    if settings.is_strict_env:
        from starlette.middleware.trustedhost import TrustedHostMiddleware
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

    # 1. Custom Security Headers & Correlation ID
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(AuthRateLimitMiddleware)

    # 2. CORS configuration (permits any localhost / 127.0.0.1 port in dev/desktop, exact allowlist only in prod/staging)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_origin_regex=None if settings.is_strict_env else r"^https?:\/\/(localhost|127\.0\.0\.1)(:[0-9]+)?$",
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token", "Accept", "Origin"],
    )

    # 3. Centralized Exception Handlers
    app.add_exception_handler(AppSecException, appsec_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # 4. Mount API Routes
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    # Root route for API discovery
    @app.get("/", tags=["Discovery"])
    def root_discovery():
        payload = {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "organization": settings.ORGANIZATION,
            "status": "operational",
            "health": f"{settings.API_V1_PREFIX}/health",
        }
        if docs_url is not None:
            payload["documentation"] = docs_url
        return payload

    # Top-level health endpoints
    @app.get("/health", tags=["Health & Diagnostics"])
    @app.get("/api/health", tags=["Health & Diagnostics"])
    def top_level_health():
        from .api.v1.endpoints.health import get_service_health
        return get_service_health()

    @app.get("/live", tags=["Health & Diagnostics"])
    def top_level_live():
        from .api.v1.endpoints.health import liveness_probe
        return liveness_probe()

    @app.get("/ready", tags=["Health & Diagnostics"])
    def top_level_ready():
        from .api.v1.endpoints.health import readiness_probe
        return readiness_probe()

    return app


app = create_application()
