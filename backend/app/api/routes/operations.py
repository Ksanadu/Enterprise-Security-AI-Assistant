"""Security-only notification diagnostics and controlled retries."""

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from app.api.deps import DbSession, require_roles
from app.core.enums import Role
from app.core.time import iso_utc
from app.db.models import NotificationOutbox, User
from app.security.audit import record_audit
from app.services.notifications import retry
from app.services.operations_status import snapshot

router = APIRouter(prefix="/operations", tags=["operations"])


@router.get("/status")
def operational_status(
    request: Request, session: DbSession, user: User = Depends(require_roles(Role.SECURITY))
):
    del user
    knowledge = getattr(request.app.state, "knowledge", None)
    return snapshot(
        session,
        request.app.state.settings,
        knowledge_ready=bool(knowledge is not None and knowledge.is_ready()),
    )


def notification_out(row: NotificationOutbox) -> dict:
    return {
        "id": row.id,
        "ticket_reference": row.ticket_reference,
        "kind": row.kind,
        "severity": row.severity,
        "status": row.status,
        "attempts": row.attempts,
        "error_code": row.error_code,
        "next_attempt_at": iso_utc(row.next_attempt_at),
        "created_at": iso_utc(row.created_at),
        "delivered_at": iso_utc(row.delivered_at),
    }


@router.get("/notifications")
def notifications(
    request: Request,
    session: DbSession,
    user: User = Depends(require_roles(Role.SECURITY)),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    del user
    rows = session.scalars(
        select(NotificationOutbox)
        .order_by(NotificationOutbox.created_at.desc(), NotificationOutbox.id)
        .offset(offset)
        .limit(limit)
    ).all()
    total = session.scalar(select(func.count()).select_from(NotificationOutbox)) or 0
    return {
        "notifications": [notification_out(row) for row in rows],
        "total": total,
        "next_offset": offset + len(rows) if offset + len(rows) < total else None,
        "receiver_configured": bool(request.app.state.settings.notification_webhook_url),
    }


@router.post("/notifications/{event_id}/retry")
def retry_notification(
    event_id: str,
    request: Request,
    session: DbSession,
    user: User = Depends(require_roles(Role.SECURITY)),
):
    row = retry(session, event_id, request.app.state.settings)
    record_audit(
        session,
        action="notification.retry_requested",
        actor=user,
        resource_type="notification",
        resource_id=row.id,
    )
    session.commit()
    return notification_out(row)
