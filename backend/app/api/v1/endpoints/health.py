"""Health-check and readiness endpoints."""
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ....core.config import settings
from ....db.session import check_db_connection, get_db
from ....schemas.health import HealthResponse, DatabaseHealth

router = APIRouter()
START_TIME = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Comprehensive service and database health check",
    description="Returns service availability, version, environment, database status, and uptime.",
)
def get_service_health() -> HealthResponse:
    db_connected = check_db_connection()
    dialect = "sqlite" if settings.is_sqlite else "postgresql"
    uptime = round(time.time() - START_TIME, 2)

    status_str = "ok" if db_connected else "degraded"

    return HealthResponse(
        status=status_str,
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        offline_mode=settings.OFFLINE_MODE,
        timestamp=datetime.now(timezone.utc),
        database=DatabaseHealth(
            status="connected" if db_connected else "disconnected",
            dialect=dialect,
        ),
        uptime_seconds=uptime,
    )


@router.get(
    "/health/jobs",
    summary="Durable job queue, outbox, lease, and worker operational telemetry",
    description="Returns queue depth, pending outbox events, active/running/retrying jobs, expired leases, worker heartbeat age, and latency metrics without sensitive job contents.",
)
def get_jobs_health(db: Session = Depends(get_db)) -> JSONResponse:
    from ....core.jobs import get_job_operational_metrics
    metrics = get_job_operational_metrics(db=db)
    return JSONResponse(status_code=status.HTTP_200_OK, content=metrics)


@router.get(
    "/ready",
    summary="Kubernetes / Docker readiness probe",
    description="Returns 200 OK only when backend database (and Redis in strict mode when configured) connections are verified.",
)
@router.get(
    "/health/ready",
    summary="Kubernetes / Docker readiness probe (alias)",
)
def readiness_probe() -> JSONResponse:
    db_ok = check_db_connection()
    if not db_ok:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "database_unavailable", "database": "disconnected"},
        )
    if settings.is_strict_env and settings.REDIS_URL:
        from ....core.jobs import get_job_redis_client
        r_client = get_job_redis_client()
        try:
            if r_client is None or not r_client.ping():
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"status": "redis_unavailable", "database": "connected", "redis": "disconnected"},
                )
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "redis_unavailable", "database": "connected", "redis": "disconnected"},
            )
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready"})


@router.get(
    "/live",
    summary="Kubernetes / Docker liveness probe",
    description="Returns 200 OK if the ASGI process is running.",
)
@router.get(
    "/health/live",
    summary="Kubernetes / Docker liveness probe (alias)",
)
def liveness_probe() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "alive"})
