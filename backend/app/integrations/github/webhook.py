"""GitHub Webhook security validator with HMAC-SHA256 signature check and replay defense."""
from datetime import datetime, timezone
import hashlib
import hmac
import re
from typing import Optional, Tuple
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...core.errors import AppSecException
from ...core.logging import get_logger
from ...models.github import WebhookDelivery

logger = get_logger("redmercury.github.webhook")
_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class WebhookSecurityError(AppSecException):
    def __init__(self, message: str = "Webhook security verification failed"):
        super().__init__(message=message, code="WEBHOOK_SECURITY_ERROR", status_code=403)


def verify_webhook_signature(
    raw_payload: bytes,
    signature_header: Optional[str],
    webhook_secret: str,
) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature using constant-time comparison.

    Header format: sha256=<64-char hex_digest>
    """
    if not signature_header or not isinstance(signature_header, str) or not webhook_secret:
        logger.warning("Webhook verification failed: missing signature header or secret")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning("Webhook verification failed: invalid signature scheme")
        return False

    expected_sig = signature_header[7:].strip().lower()
    if not _HEX64_RE.match(expected_sig):
        logger.warning("Webhook verification failed: malformed sha256 digest length or characters")
        return False

    computed_mac = hmac.new(
        key=webhook_secret.encode("utf-8"),
        msg=raw_payload,
        digestmod=hashlib.sha256,
    ).hexdigest().lower()

    # Constant-time comparison prevents timing attacks
    is_valid = hmac.compare_digest(expected_sig, computed_mac)
    if not is_valid:
        logger.warning("Webhook signature mismatch detected")
    return is_valid


def claim_webhook_delivery(
    db: Session,
    delivery_id: Optional[str],
    event_type: str,
    raw_payload: bytes,
) -> Tuple[bool, Optional[str]]:
    """Atomically claim an authenticated X-GitHub-Delivery GUID for processing.

    - Must ONLY be called AFTER HMAC-SHA256 signature verification succeeds.
    - Rejects duplicate deliveries in 'processing', 'processed', or 'completed' states.
    - Permits retry if a previous authenticated attempt ended in 'failed' state.
    - Handles concurrent duplicate inserts via IntegrityError / conditional UPDATE.
    """
    if not delivery_id or not str(delivery_id).strip():
        return False, "Missing X-GitHub-Delivery header (required for replay defense)"

    delivery_clean = str(delivery_id).strip()
    payload_hash = hashlib.sha256(raw_payload).hexdigest()

    existing = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_clean).first()
    if existing is not None:
        if existing.status == "failed":
            # Allow authenticated retry of a previously failed delivery via atomic claim
            claimed = (
                db.query(WebhookDelivery)
                .filter(WebhookDelivery.id == delivery_clean, WebhookDelivery.status == "failed")
                .update(
                    {
                        "status": "processing",
                        "payload_sha256": payload_hash,
                        "received_at": datetime.now(timezone.utc),
                    },
                    synchronize_session=False,
                )
            )
            db.commit()
            if claimed == 1:
                return True, None
        logger.warning(f"Replay attack or duplicate delivery blocked: {delivery_clean}")
        return False, f"Duplicate webhook delivery ID '{delivery_clean}' already processed (replay blocked)"

    record = WebhookDelivery(
        id=delivery_clean,
        event_type=event_type,
        payload_sha256=payload_hash,
        status="processing",
    )
    try:
        db.add(record)
        db.commit()
        return True, None
    except IntegrityError:
        db.rollback()
        logger.warning(f"Concurrent duplicate webhook delivery blocked: {delivery_clean}")
        return False, f"Duplicate webhook delivery ID '{delivery_clean}' already processed (replay blocked)"


def finalize_webhook_delivery(
    db: Session,
    delivery_id: str,
    status: str = "completed",
) -> None:
    """Update claimed WebhookDelivery status to 'completed' or 'failed'."""
    delivery_clean = (delivery_id or "").strip()
    if not delivery_clean:
        return
    try:
        db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_clean).update(
            {"status": status},
            synchronize_session=False,
        )
        db.commit()
    except Exception:
        db.rollback()


def record_and_check_replay(
    db: Session,
    delivery_id: Optional[str],
    event_type: str,
    raw_payload: bytes,
) -> Tuple[bool, Optional[str]]:
    """Check X-GitHub-Delivery GUID to prevent webhook replay attacks."""
    accepted, err = claim_webhook_delivery(
        db=db,
        delivery_id=delivery_id,
        event_type=event_type,
        raw_payload=raw_payload,
    )
    if accepted and delivery_id:
        finalize_webhook_delivery(db=db, delivery_id=delivery_id, status="processed")
    return accepted, err


# Convenient aliases
verify_github_signature = verify_webhook_signature


def record_and_check_delivery(
    db: Session,
    delivery_id: Optional[str],
    event_type: str,
    installation_id: Optional[str] = None,
    repository_id: Optional[str] = None,
    raw_payload: bytes = b"",
) -> bool:
    """Record delivery and check for replay, returning True if accepted."""
    accepted, _ = record_and_check_replay(
        db=db,
        delivery_id=delivery_id,
        event_type=event_type,
        raw_payload=raw_payload,
    )
    return accepted
