"""SQLAlchemy models for Durable Background Jobs, Transactional Outbox, and Atomic Quota Slots (Phase 6 / REL-01)."""
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class DurableJob(Base, TimestampMixin):
    """Authoritative database state for long-running background jobs (scans, verifications, webhooks).

    Enforces:
    - Centralized state machine lifecycle (queued, running, retrying, completed, failed, cancelling, cancelled, interrupted).
    - Lease-based atomic worker claiming with fencing tokens (lease_token) to prevent stale worker overwrites.
    - Periodic worker heartbeats and deterministic lease expiration recovery.
    - Tenant-scoped idempotency key uniqueness.
    - Bounded retries with exponential backoff + jitter.
    """
    __tablename__ = "durable_jobs"

    __table_args__ = (
        UniqueConstraint("job_type", "resource_id", name="uq_durable_jobs_type_resource"),
        UniqueConstraint(
            "tenant_id",
            "job_type",
            "idempotency_key",
            name="uq_durable_jobs_tenant_type_idempotency",
        ),
        Index("ix_durable_jobs_status_retry", "status", "next_retry_at"),
        Index("ix_durable_jobs_lease_expires", "status", "lease_expires_at"),
        Index("ix_durable_jobs_tenant_type_status", "tenant_id", "job_type", "status"),
    )

    id = Column(String(64), primary_key=True, default=generate_uuid)
    job_type = Column(String(32), nullable=False, index=True)  # "scan", "verification", "webhook"
    resource_id = Column(String(64), nullable=False, index=True)  # scan.id, verification_run.id, webhook_delivery.id
    tenant_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    repository_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True, index=True)
    idempotency_key = Column(String(128), nullable=True, index=True)

    # Lifecycle state: queued, running, retrying, completed, failed, cancelling, cancelled, interrupted
    status = Column(String(32), default="queued", nullable=False, index=True)
    payload_json = Column(Text, nullable=True)

    # Attempt & retry tracking
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)

    # Lease & worker ownership fencing
    worker_id = Column(String(128), nullable=True, index=True)
    lease_token = Column(String(64), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True)
    heartbeat_at = Column(DateTime(timezone=True), nullable=True)

    # Lifecycle timestamps
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    failed_at = Column(DateTime(timezone=True), nullable=True)
    cancel_requested_at = Column(DateTime(timezone=True), nullable=True)

    # Safe failure categorization (no raw internal tracebacks or secrets)
    failure_category = Column(String(64), nullable=True)
    error_detail = Column(Text, nullable=True)

    # Quota reservation & usage accounting
    quota_reserved = Column(Boolean, default=True, nullable=False)
    quota_counted = Column(Boolean, default=False, nullable=False)

    # Relationships
    outbox_events = relationship(
        "JobOutboxEvent",
        back_populates="job",
        cascade="all, delete-orphan",
    )
    active_slot = relationship(
        "ActiveJobSlot",
        back_populates="job",
        uselist=False,
        cascade="all, delete-orphan",
    )


class JobOutboxEvent(Base, TimestampMixin):
    """Transactional outbox record created in the same database transaction as DurableJob.

    Eliminates the database/Redis dual-write problem:
    - Created with status='pending' when the job is committed to the DB.
    - Marked status='dispatched' only after Redis confirms enqueueing.
    - Recovered on startup or periodic sweep if Redis was temporarily unreachable.
    """
    __tablename__ = "job_outbox_events"

    __table_args__ = (
        Index("ix_job_outbox_events_status_created", "status", "created_at"),
    )

    id = Column(String(64), primary_key=True, default=generate_uuid)
    job_id = Column(String(64), ForeignKey("durable_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    job_type = Column(String(32), nullable=False)
    resource_id = Column(String(64), nullable=False)
    queue_name = Column(String(64), default="redmercury:jobs:queue", nullable=False)

    # Status: pending, dispatched, cancelled
    status = Column(String(32), default="pending", nullable=False, index=True)
    dispatch_attempts = Column(Integer, default=0, nullable=False)
    dispatched_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)

    job = relationship("DurableJob", back_populates="outbox_events")


class ActiveJobSlot(Base, TimestampMixin):
    """Database-enforced atomic concurrency and single-active-repository-scan reservation slot.

    Uses database-level UniqueConstraints so concurrent transactions across multiple API
    workers cannot exceed MAX_CONCURRENT_SCANS_PER_USER / MAX_CONCURRENT_VERIFICATIONS_PER_USER
    or launch two concurrent active scans on the same repository.
    """
    __tablename__ = "active_job_slots"

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "job_type",
            "slot_number",
            name="uq_active_job_slots_tenant_type_slot",
        ),
    )

    id = Column(String(64), primary_key=True, default=generate_uuid)
    job_id = Column(String(64), ForeignKey("durable_jobs.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    tenant_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    job_type = Column(String(32), nullable=False, index=True)
    slot_number = Column(Integer, nullable=False)
    repository_active_lock = Column(String(128), nullable=True, unique=True, index=True)

    job = relationship("DurableJob", back_populates="active_slot")
