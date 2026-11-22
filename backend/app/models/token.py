"""SQLAlchemy models for revoked JWT access tokens and rotating refresh-token sessions."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String

from ..db.base import Base, generate_uuid


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    jti = Column(String(64), nullable=True, index=True)
    user_id = Column(String(64), nullable=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=True, index=True)
    revoked_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    reason = Column(String(64), default="logout", nullable=False)

    @property
    def revocation_reason(self) -> str:
        return self.reason

    @revocation_reason.setter
    def revocation_reason(self, value: str) -> None:
        self.reason = value


class RefreshTokenSession(Base):
    """Server-side rotating refresh-token session with family-based reuse detection."""
    __tablename__ = "refresh_token_sessions"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    family_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    parent_token_hash = Column(String(64), nullable=True)
    replaced_by_hash = Column(String(64), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True, index=True)
    revoke_reason = Column(String(64), nullable=True)

