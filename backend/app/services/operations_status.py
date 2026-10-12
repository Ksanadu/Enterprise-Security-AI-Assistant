"""Database-backed operational gauges without incident text or identities."""

import datetime as dt

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.enums import Severity, TicketStatus
from app.core.time import iso_utc
from app.db.models import AuditLog, NotificationOutbox, Ticket, WorkflowTask
from app.security.acknowledgment import incident_time_expression, response_absent_predicate


def snapshot(
    session: Session, settings: Settings, *, knowledge_ready: bool, now: dt.datetime | None = None
) -> dict:
    now = now or dt.datetime.now(dt.UTC)
    cutoff = now - dt.timedelta(minutes=60)
    stale = now - dt.timedelta(minutes=5)
    workflow: dict[str, int] = dict(
        session.execute(select(WorkflowTask.status, func.count()).group_by(WorkflowTask.status))
        .tuples()
        .all()
    )
    notification: dict[str, int] = dict(
        session.execute(
            select(NotificationOutbox.status, func.count()).group_by(NotificationOutbox.status)
        )
        .tuples()
        .all()
    )
    workflow_stale = (
        session.scalar(
            select(func.count())
            .select_from(WorkflowTask)
            .where(
                WorkflowTask.status.in_(["pending", "processing"]), WorkflowTask.created_at <= stale
            )
        )
        or 0
    )
    notification_stale = (
        session.scalar(
            select(func.count())
            .select_from(NotificationOutbox)
            .where(
                NotificationOutbox.status.in_(["pending", "processing"]),
                NotificationOutbox.created_at <= stale,
            )
        )
        or 0
    )
    # An escalation requires a new human response after its incident was recorded.
    no_response = response_absent_predicate()
    open_incident = (
        Ticket.severity.in_([Severity.HIGH, Severity.CRITICAL]),
        Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
    )
    missing = (
        session.scalar(
            select(func.count())
            .select_from(Ticket)
            .where(
                *open_incident,
                no_response,
                ~select(NotificationOutbox.id)
                .where(
                    NotificationOutbox.ticket_id == Ticket.id,
                    NotificationOutbox.kind == "incident",
                    NotificationOutbox.severity == Ticket.severity,
                )
                .exists(),
            )
        )
        or 0
    )
    overdue = {}
    for severity, seconds in (
        (Severity.HIGH, settings.notification_high_ack_seconds),
        (Severity.CRITICAL, settings.notification_critical_ack_seconds),
    ):
        overdue[severity.value] = (
            session.scalar(
                select(func.count(Ticket.id))
                .select_from(Ticket)
                .where(
                    Ticket.severity == severity,
                    Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
                    incident_time_expression() <= now - dt.timedelta(seconds=seconds),
                    no_response,
                )
            )
            or 0
        )
    usage = AuditLog.detail["model_usage"]
    failures = (
        session.scalar(
            select(func.coalesce(func.sum(usage["failures"].as_integer()), 0)).where(
                AuditLog.action == "chat.query.answered", AuditLog.created_at >= cutoff
            )
        )
        or 0
    )
    exhausted = (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.action == "chat.query.answered",
                AuditLog.created_at >= cutoff,
                usage["budget_exhausted"].as_boolean().is_(True),
            )
        )
        or 0
    )
    workflow_failures = (
        session.scalar(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.action == "workflow.failed", AuditLog.created_at >= cutoff)
        )
        or 0
    )
    alerts = []
    for code, active in (
        ("knowledge_unavailable", not knowledge_ready),
        ("notification_receiver_unconfigured", not settings.notification_webhook_url),
        ("workflow_backlog_over_5m", workflow_stale > 0),
        ("notification_backlog_over_5m", notification_stale > 0),
        ("notification_retry_exhausted", notification.get("exhausted", 0) > 0),
        ("high_risk_notification_missing", missing > 0),
        ("high_risk_response_overdue", sum(overdue.values()) > 0),
        ("model_failures_last_hour", failures > 0 or exhausted > 0),
        ("workflow_failures_last_hour", workflow_failures > 0),
    ):
        if active:
            alerts.append(code)
    return {
        "generated_at": iso_utc(now),
        "window_minutes": 60,
        "knowledge_ready": knowledge_ready,
        "workflow": {
            "by_status": workflow,
            "stale_count": workflow_stale,
            "recent_failures": workflow_failures,
        },
        "notifications": {
            "by_status": notification,
            "stale_count": notification_stale,
            "receiver_configured": bool(settings.notification_webhook_url),
            "missing_incident_count": missing,
        },
        "response_overdue": overdue,
        "model": {"recent_network_failures": failures, "recent_budget_exhaustions": exhausted},
        "alerts": alerts,
    }
