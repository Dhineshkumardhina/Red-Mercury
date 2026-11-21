"""Sync model constraints, indexes, nullability, and status column lengths.

Revision ID: 0011_sync_model_constraints
Revises: 0010_make_patch_proposal_id_nullable
Create Date: 2026-10-19 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0011_sync_model_constraints"
down_revision: Union[str, None] = "0010_make_patch_proposal_id_nullable"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Indexes on audit_events
    op.create_index(
        "ix_audit_events_resource_identifier",
        "audit_events",
        ["resource_identifier"],
        unique=False,
    )

    # 2. Missing query indexes on pull_request_scans
    op.create_index(
        "ix_pr_scans_scan_id",
        "pull_request_scans",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_pr_scans_status",
        "pull_request_scans",
        ["status"],
        unique=False,
    )

    # 3. Alter repositories: owner_id NOT NULL and change name index from unique to non-unique
    bind = op.get_bind()
    # Verify no orphaned repositories exist before enforcing NOT NULL
    orphaned_count = bind.execute(
        sa.text("SELECT COUNT(*) FROM repositories WHERE owner_id IS NULL")
    ).scalar()
    if orphaned_count and orphaned_count > 0:
        raise ValueError(
            f"Cannot enforce NOT NULL on repositories.owner_id: {orphaned_count} repositories have NULL owner_id."
        )

    # Drop unique index on repositories.name and recreate as non-unique
    op.drop_index("ix_repositories_name", table_name="repositories")
    op.create_index(
        "ix_repositories_name",
        "repositories",
        ["name"],
        unique=False,
    )

    with op.batch_alter_table("repositories") as batch_op:
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=64),
            existing_nullable=True,
            nullable=False,
        )

    # 4. Alter verification_runs.status from VARCHAR(32) to String(64)
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=32),
            type_=sa.String(length=64),
            existing_nullable=False,
            existing_server_default=sa.text("'pending'"),
        )

    # 5. Create finding_analyses table if not already present (for fresh database installs)
    inspector = sa.inspect(bind)
    if not inspector.has_table("finding_analyses"):
        op.create_table(
            "finding_analyses",
            sa.Column("id", sa.String(length=64), primary_key=True),
            sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False),
            sa.Column("repo_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
            sa.Column("plain_language_explanation", sa.Text(), nullable=False),
            sa.Column("potential_impact", sa.Text(), nullable=False),
            sa.Column("relevant_code_evidence", sa.Text(), nullable=False),
            sa.Column("likely_root_cause", sa.Text(), nullable=False),
            sa.Column("suggested_remediation", sa.Text(), nullable=False),
            sa.Column("suggested_targeted_tests", sa.Text(), nullable=False),
            sa.Column("missing_context", sa.Text(), nullable=True),
            sa.Column("limitations", sa.Text(), nullable=True),
            sa.Column("ai_model", sa.String(length=64), nullable=False, server_default="gemini-2.5-flash"),
            sa.Column("analysis_timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("confidence", sa.String(length=32), nullable=False, server_default="HIGH"),
            sa.Column("is_exploitable_claim_supported", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("requires_human_review", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("user_authorized", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_finding_analyses_finding_id", "finding_analyses", ["finding_id"])
        op.create_index("ix_finding_analyses_repo_id", "finding_analyses", ["repo_id"])


def downgrade() -> None:
    # 4. Revert verification_runs.status from String(64) to String(32)
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.String(length=64),
            type_=sa.String(length=32),
            existing_nullable=False,
            existing_server_default=sa.text("'pending'"),
        )

    # 3. Revert repositories.owner_id to nullable=True and name index to unique=True
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.alter_column(
            "owner_id",
            existing_type=sa.String(length=64),
            existing_nullable=False,
            nullable=True,
        )

    bind = op.get_bind()
    # Disambiguate duplicate repository names if multi-tenant rows were created on revision 0011
    duplicates = bind.execute(sa.text("""
        SELECT name FROM repositories GROUP BY name HAVING COUNT(*) > 1
    """)).fetchall()
    for row in duplicates:
        dup_name = row[0]
        repos = bind.execute(sa.text(
            "SELECT id FROM repositories WHERE name = :name ORDER BY created_at"
        ), {"name": dup_name}).fetchall()
        for idx, r in enumerate(repos[1:], start=2):
            bind.execute(sa.text(
                "UPDATE repositories SET name = :new_name WHERE id = :id"
            ), {"new_name": f"{dup_name}-{idx}", "id": r[0]})

    op.drop_index("ix_repositories_name", table_name="repositories")
    op.create_index(
        "ix_repositories_name",
        "repositories",
        ["name"],
        unique=True,
    )

    # 2. Drop pull_request_scans indexes
    op.drop_index("ix_pr_scans_status", table_name="pull_request_scans")
    op.drop_index("ix_pr_scans_scan_id", table_name="pull_request_scans")

    # 1. Drop audit_events index
    op.drop_index("ix_audit_events_resource_identifier", table_name="audit_events")

    # 0. Drop finding_analyses table if present
    inspector = sa.inspect(bind)
    if inspector.has_table("finding_analyses"):
        op.drop_table("finding_analyses")
