"""Audit history query API endpoints."""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from ....core.auth import get_current_user
from ....db.session import get_db
from ....models.audit import AuditEvent
from ....models.user import User

router = APIRouter()


class AuditEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_id: Optional[str] = None
    action: str
    resource_type: str
    resource_identifier: Optional[str] = None
    timestamp: datetime
    safe_metadata: Optional[str] = None


@router.get(
    "",
    response_model=List[AuditEventRead],
    summary="List sanitized audit events for the authenticated user",
)
def list_audit_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None, description="Optional action filter"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[AuditEvent]:
    query = db.query(AuditEvent).filter(AuditEvent.actor_id == current_user.id)
    if action and action.strip():
        query = query.filter(AuditEvent.action == action.strip())
    return query.order_by(AuditEvent.timestamp.desc()).offset(skip).limit(limit).all()
