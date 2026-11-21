"""Make verification_runs.patch_proposal_id nullable in SQLite and PostgreSQL.

Revision ID: 0010_make_patch_proposal_id_nullable
Revises: 0009_add_commit_sha_to_scans
Create Date: 2026-10-18 21:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0010_make_patch_proposal_id_nullable"
down_revision: Union[str, None] = "0009_add_commit_sha_to_scans"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Make patch_proposal_id nullable.

    Pass existing_nullable=False explicitly so Alembic's batch table recreation
    in SQLite drops the NOT NULL constraint properly.
    """
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column(
            "patch_proposal_id",
            existing_type=sa.String(length=64),
            existing_nullable=False,
            nullable=True,
        )


def downgrade() -> None:
    """Restore NOT NULL constraint on patch_proposal_id.

    To prevent integrity failure when downgrading databases with ad-hoc verification
    runs (where patch_proposal_id IS NULL), clean up orphaned records first before
    re-applying NOT NULL.
    """
    bind = op.get_bind()
    # Remove dependent evidence rows for any verification runs with NULL patch_proposal_id
    bind.execute(sa.text("""
        DELETE FROM verification_evidence 
        WHERE verification_run_id IN (
            SELECT id FROM verification_runs WHERE patch_proposal_id IS NULL
        )
    """))
    bind.execute(sa.text("""
        DELETE FROM security_evidence 
        WHERE verification_run_id IN (
            SELECT id FROM verification_runs WHERE patch_proposal_id IS NULL
        )
    """))
    bind.execute(sa.text("DELETE FROM verification_runs WHERE patch_proposal_id IS NULL"))

    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column(
            "patch_proposal_id",
            existing_type=sa.String(length=64),
            existing_nullable=True,
            nullable=False,
        )
