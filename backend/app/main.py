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
from .core.security import AuthRateLimitMiddleware, RequestSizeLimitMiddleware, SecurityHeadersMiddleware, hash_password
from .db.base import Base
from .db.session import engine, SessionLocal
from .models.user import User
from .models.repository import Repository
from .models.finding import SecurityFinding
from .models.verification import VerificationRun

# Initialize structured logging
setup_logging(level=settings.LOG_LEVEL, json_format=settings.LOG_FORMAT_JSON)
logger = get_logger("redmercury.main")


def seed_initial_dev_data() -> None:
    """Ensure at least one user exists for local testing without dummy entities."""
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            dev_user = User(
                id="ade14bbe-e0f0-4c8e-beff-ff9f720fe288",
                email="dhineshkumardhina@gmail.com",
                password_hash=hash_password(settings.DEV_SEED_PASSWORD),
                account_status="active",
                role="admin",
            )
            db.add(dev_user)
            db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning(f"User initialization skipped: {exc}")
    finally:
        db.close()


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

                HEAD_REVISION = "0012_add_revoked_tokens_and_user_role"
                if has_alembic and current_rev != HEAD_REVISION:
                    command.upgrade(cfg, "head")
                elif not has_alembic:
                    command.stamp(cfg, "head")
        except Exception as exc:
            logger.warning(f"Database schema auto-migration check skipped: {exc}")
        seed_initial_dev_data()

    # Reconcile any interrupted or hanging jobs from previous server restarts
    try:
        reconcile_db = SessionLocal()
        from .core.quotas import reconcile_interrupted_jobs
        reconcile_interrupted_jobs(reconcile_db)
        reconcile_db.close()
    except Exception as exc:
        logger.warning(f"Failed to reconcile interrupted jobs on startup: {exc}")

    yield

    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_application() -> FastAPI:
    """FastAPI application factory."""
    docs_url = "/docs" if (settings.DOCS_ENABLED and not settings.is_production) else None
    redoc_url = "/redoc" if (settings.DOCS_ENABLED and not settings.is_production) else None
    openapi_url = f"{settings.API_V1_PREFIX}/openapi.json" if (settings.DOCS_ENABLED and not settings.is_production) else None

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
    if settings.is_production:
        from starlette.middleware.trustedhost import TrustedHostMiddleware
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

    # 1. Custom Security Headers & Correlation ID
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(AuthRateLimitMiddleware)

    # 2. CORS configuration (permits any localhost / 127.0.0.1 port in dev/desktop, exact in prod)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_origin_regex=r"^https?:\/\/(localhost|127\.0\.0\.1)(:[0-9]+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
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
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "organization": settings.ORGANIZATION,
            "status": "operational",
            "documentation": "/docs",
            "health": f"{settings.API_V1_PREFIX}/health",
        }

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
