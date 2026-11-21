"""SQLAlchemy model for tracking revoked JWT access tokens."""
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

