"""Add revoked_tokens table and role column to users.

Revision ID: 0012_add_revoked_tokens_and_user_role
Revises: 0011_sync_model_constraints
Create Date: 2026-10-28 13:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0012_add_revoked_tokens_and_user_role"
down_revision: Union[str, None] = "0011_sync_model_constraints"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # 1. Add role column to users table with default 'admin' if not present
    if "users" in existing_tables:
        user_columns = [c["name"] for c in inspector.get_columns("users")]
        if "role" not in user_columns:
            op.add_column(
                "users",
                sa.Column("role", sa.String(length=32), nullable=False, server_default="admin"),
            )
        existing_indices = [idx["name"] for idx in inspector.get_indexes("users")]
        if "ix_users_role" not in existing_indices:
            op.create_index("ix_users_role", "users", ["role"], unique=False)
    else:
        op.add_column(
            "users",
            sa.Column("role", sa.String(length=32), nullable=False, server_default="admin"),
        )
        op.create_index("ix_users_role", "users", ["role"], unique=False)

    # 2. Create revoked_tokens table for server-side JWT invalidation on logout
    if "revoked_tokens" not in existing_tables:
        op.create_table(
            "revoked_tokens",
            sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("jti", sa.String(length=64), nullable=True),
            sa.Column("user_id", sa.String(length=64), nullable=True),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("reason", sa.String(length=64), nullable=False, server_default="logout"),
        )
        op.create_index("ix_revoked_tokens_token_hash", "revoked_tokens", ["token_hash"], unique=True)
        op.create_index("ix_revoked_tokens_jti", "revoked_tokens", ["jti"], unique=False)
        op.create_index("ix_revoked_tokens_user_id", "revoked_tokens", ["user_id"], unique=False)
        op.create_index("ix_revoked_tokens_expires_at", "revoked_tokens", ["expires_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    if "revoked_tokens" in existing_tables:
        existing_indices = [idx["name"] for idx in inspector.get_indexes("revoked_tokens")]
        for idx_name in [
            "ix_revoked_tokens_expires_at",
            "ix_revoked_tokens_user_id",
            "ix_revoked_tokens_jti",
            "ix_revoked_tokens_token_hash",
        ]:
            if idx_name in existing_indices:
                op.drop_index(idx_name, table_name="revoked_tokens")
        op.drop_table("revoked_tokens")

    if "users" in existing_tables:
        user_columns = [c["name"] for c in inspector.get_columns("users")]
        if "role" in user_columns:
            existing_indices = [idx["name"] for idx in inspector.get_indexes("users")]
            if "ix_users_role" in existing_indices:
                op.drop_index("ix_users_role", table_name="users")
            op.drop_column("users", "role")

