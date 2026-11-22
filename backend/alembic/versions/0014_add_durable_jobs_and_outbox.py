"""Add durable_jobs, job_outbox_events, and active_job_slots tables (Phase 6 / REL-01).

Revision ID: 0014_add_durable_jobs_and_outbox
Revises: 0013_add_refresh_token_sessions
Create Date: 2026-11-21
"""
from alembic import op
import sqlalchemy as sa


revision = "0014_add_durable_jobs_and_outbox"
down_revision = "0013_add_refresh_token_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. durable_jobs
    op.create_table(
        "durable_jobs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("repository_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True),
        sa.Column("idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("worker_id", sa.String(length=128), nullable=True),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_category", sa.String(length=64), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("quota_reserved", sa.Boolean(), nullable=False),
        sa.Column("quota_counted", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_type", "resource_id", name="uq_durable_jobs_type_resource"),
        sa.UniqueConstraint("tenant_id", "job_type", "idempotency_key", name="uq_durable_jobs_tenant_type_idempotency"),
    )
    op.create_index("ix_durable_jobs_job_type", "durable_jobs", ["job_type"], unique=False)
    op.create_index("ix_durable_jobs_resource_id", "durable_jobs", ["resource_id"], unique=False)
    op.create_index("ix_durable_jobs_tenant_id", "durable_jobs", ["tenant_id"], unique=False)
    op.create_index("ix_durable_jobs_repository_id", "durable_jobs", ["repository_id"], unique=False)
    op.create_index("ix_durable_jobs_idempotency_key", "durable_jobs", ["idempotency_key"], unique=False)
    op.create_index("ix_durable_jobs_status", "durable_jobs", ["status"], unique=False)
    op.create_index("ix_durable_jobs_worker_id", "durable_jobs", ["worker_id"], unique=False)
    op.create_index("ix_durable_jobs_status_retry", "durable_jobs", ["status", "next_retry_at"], unique=False)
    op.create_index("ix_durable_jobs_lease_expires", "durable_jobs", ["status", "lease_expires_at"], unique=False)
    op.create_index("ix_durable_jobs_tenant_type_status", "durable_jobs", ["tenant_id", "job_type", "status"], unique=False)

    # 2. job_outbox_events
    op.create_table(
        "job_outbox_events",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), sa.ForeignKey("durable_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("resource_id", sa.String(length=64), nullable=False),
        sa.Column("queue_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("dispatch_attempts", sa.Integer(), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_job_outbox_events_job_id", "job_outbox_events", ["job_id"], unique=False)
    op.create_index("ix_job_outbox_events_status", "job_outbox_events", ["status"], unique=False)
    op.create_index("ix_job_outbox_events_status_created", "job_outbox_events", ["status", "created_at"], unique=False)

    # 3. active_job_slots
    op.create_table(
        "active_job_slots",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("job_id", sa.String(length=64), sa.ForeignKey("durable_jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("slot_number", sa.Integer(), nullable=False),
        sa.Column("repository_active_lock", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "job_type", "slot_number", name="uq_active_job_slots_tenant_type_slot"),
    )
    op.create_index("ix_active_job_slots_job_id", "active_job_slots", ["job_id"], unique=True)
    op.create_index("ix_active_job_slots_tenant_id", "active_job_slots", ["tenant_id"], unique=False)
    op.create_index("ix_active_job_slots_job_type", "active_job_slots", ["job_type"], unique=False)
    op.create_index("ix_active_job_slots_repository_active_lock", "active_job_slots", ["repository_active_lock"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_active_job_slots_repository_active_lock", table_name="active_job_slots")
    op.drop_index("ix_active_job_slots_job_type", table_name="active_job_slots")
    op.drop_index("ix_active_job_slots_tenant_id", table_name="active_job_slots")
    op.drop_index("ix_active_job_slots_job_id", table_name="active_job_slots")
    op.drop_table("active_job_slots")

    op.drop_index("ix_job_outbox_events_status_created", table_name="job_outbox_events")
    op.drop_index("ix_job_outbox_events_status", table_name="job_outbox_events")
    op.drop_index("ix_job_outbox_events_job_id", table_name="job_outbox_events")
    op.drop_table("job_outbox_events")

    op.drop_index("ix_durable_jobs_tenant_type_status", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_lease_expires", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_status_retry", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_worker_id", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_status", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_idempotency_key", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_repository_id", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_tenant_id", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_resource_id", table_name="durable_jobs")
    op.drop_index("ix_durable_jobs_job_type", table_name="durable_jobs")
    op.drop_table("durable_jobs")
