"""Add refresh_token_sessions table for rotating HttpOnly refresh sessions.

Revision ID: 0013_add_refresh_token_sessions
Revises: 0012_add_revoked_tokens_and_user_role
Create Date: 2026-11-21
"""
from alembic import op
import sqlalchemy as sa


revision = "0013_add_refresh_token_sessions"
down_revision = "0012_add_revoked_tokens_and_user_role"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "refresh_token_sessions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("family_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("parent_token_hash", sa.String(length=64), nullable=True),
        sa.Column("replaced_by_hash", sa.String(length=64), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_refresh_token_sessions_family_id", "refresh_token_sessions", ["family_id"])
    op.create_index("ix_refresh_token_sessions_user_id", "refresh_token_sessions", ["user_id"])
    op.create_index("ix_refresh_token_sessions_token_hash", "refresh_token_sessions", ["token_hash"], unique=True)
    op.create_index("ix_refresh_token_sessions_expires_at", "refresh_token_sessions", ["expires_at"])
    op.create_index("ix_refresh_token_sessions_revoked_at", "refresh_token_sessions", ["revoked_at"])


def downgrade() -> None:
    op.drop_index("ix_refresh_token_sessions_revoked_at", table_name="refresh_token_sessions")
    op.drop_index("ix_refresh_token_sessions_expires_at", table_name="refresh_token_sessions")
    op.drop_index("ix_refresh_token_sessions_token_hash", table_name="refresh_token_sessions")
    op.drop_index("ix_refresh_token_sessions_user_id", table_name="refresh_token_sessions")
    op.drop_index("ix_refresh_token_sessions_family_id", table_name="refresh_token_sessions")
    op.drop_table("refresh_token_sessions")
