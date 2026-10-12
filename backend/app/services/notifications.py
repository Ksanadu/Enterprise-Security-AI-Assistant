"""Transactional outbox, short leases, bounded HTTP and acknowledged reminders."""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import hmac
import json
import logging
import ssl
import threading
import time
import uuid

import httpx
from sqlalchemy import exists, or_, select, update
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import Severity, TicketStatus
from app.core.errors import ConfigurationError, NotFoundError
from app.core.time import iso_utc
from app.db.models import NotificationOutbox, Ticket, TicketEvent
from app.db.session import get_session_factory
from app.security.acknowledgment import human_response_predicate, incident_time_expression
from app.security.audit import record_audit

logger = logging.getLogger(__name__)


def aware(value: dt.datetime) -> dt.datetime:
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value.astimezone(dt.UTC)


def enqueue(
    session: Session,
    ticket: Ticket,
    *,
    kind: str = "incident",
    event_key: str | None = None,
    now: dt.datetime | None = None,
    settings: Settings | None = None,
) -> None:
    if ticket.severity.rank < Severity.HIGH.rank or ticket.status in {
        TicketStatus.CLOSED,
        TicketStatus.RESOLVED,
    }:
        return
    now = now or dt.datetime.now(dt.UTC)
    settings = settings or get_settings()
    sla = (
        settings.notification_critical_ack_seconds
        if ticket.severity is Severity.CRITICAL
        else settings.notification_high_ack_seconds
    )
    session.execute(
        insert(NotificationOutbox)
        .values(
            id=str(uuid.uuid4()),
            event_key=event_key or f"incident:{ticket.id}:{ticket.severity.value}",
            ticket_id=ticket.id,
            ticket_reference=ticket.reference,
            severity=ticket.severity.value,
            kind=kind,
            status="pending",
            attempts=0,
            attempt_limit=settings.notification_max_attempts,
            created_at=now,
            next_attempt_at=now,
            next_reminder_at=now + dt.timedelta(seconds=sla) if kind == "incident" else None,
        )
        .on_conflict_do_nothing(index_elements=[NotificationOutbox.event_key])
    )


def needs_response(session: Session, ticket: Ticket, since: dt.datetime) -> bool:
    if ticket.status in {TicketStatus.CLOSED, TicketStatus.RESOLVED}:
        return False
    return not session.scalar(
        select(
            exists().where(
                TicketEvent.ticket_id == ticket.id,
                TicketEvent.created_at >= since,
                human_response_predicate(),
            )
        )
    )


def backfill_existing(session: Session, settings: Settings, limit: int = 500) -> int:
    """Bounded restart-safe reconciliation for retained pre-outbox incidents."""
    rows = session.scalars(
        select(Ticket)
        .where(
            Ticket.severity.in_([Severity.HIGH, Severity.CRITICAL]),
            Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
            ~select(NotificationOutbox.id)
            .where(
                NotificationOutbox.ticket_id == Ticket.id,
                NotificationOutbox.kind == "incident",
                NotificationOutbox.severity == Ticket.severity,
            )
            .exists(),
        )
        .order_by(Ticket.id)
        .limit(limit)
    ).all()
    for ticket in rows:
        created = session.scalar(
            select(incident_time_expression()).select_from(Ticket).where(Ticket.id == ticket.id)
        )
        created = created or ticket.created_at
        enqueue(session, ticket, now=aware(created), settings=settings)
        if not needs_response(session, ticket, created):
            session.execute(
                update(NotificationOutbox)
                .where(
                    NotificationOutbox.event_key == f"incident:{ticket.id}:{ticket.severity.value}",
                    NotificationOutbox.status == "pending",
                    NotificationOutbox.attempts == 0,
                )
                .values(
                    status="cancelled",
                    next_reminder_at=None,
                    error_code="preexisting_human_response",
                )
            )
    return len(rows)


def discover_reminders(session: Session, settings: Settings, now: dt.datetime) -> int:
    alerts = session.scalars(
        select(NotificationOutbox)
        .join(Ticket, Ticket.id == NotificationOutbox.ticket_id)
        .where(
            NotificationOutbox.kind == "incident",
            NotificationOutbox.severity == Ticket.severity,
            NotificationOutbox.next_reminder_at <= now,
            Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
        )
        .order_by(NotificationOutbox.next_reminder_at)
        .limit(500)
    ).all()
    created = 0
    for alert in alerts:
        ticket = session.get(Ticket, alert.ticket_id)
        if ticket is None:
            continue
        due = alert.next_reminder_at
        if not needs_response(session, ticket, alert.created_at):
            alert.next_reminder_at = None
            continue
        claimed = session.scalar(
            update(NotificationOutbox)
            .where(NotificationOutbox.id == alert.id, NotificationOutbox.next_reminder_at == due)
            .values(
                next_reminder_at=now
                + dt.timedelta(seconds=settings.notification_reminder_interval_seconds)
            )
            .returning(NotificationOutbox.id)
        )
        if not claimed:
            continue
        enqueue(
            session,
            ticket,
            kind="ack_timeout",
            event_key=f"ack_timeout:{alert.id}:{iso_utc(due)}",
            now=now,
        )
        created += 1
    return created


async def post_event(settings: Settings, url: str, body: bytes, event_id: str) -> None:
    timestamp = str(int(time.time()))
    signature = hmac.new(
        settings.notification_signing_secret.encode(),
        timestamp.encode() + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    async with asyncio.timeout(settings.notification_timeout_seconds):
        async with httpx.AsyncClient(
            timeout=settings.notification_timeout_seconds,
            trust_env=False,
            follow_redirects=False,
            verify=ssl.create_default_context(cafile=settings.notification_ca_bundle_file)
            if settings.notification_ca_bundle_file
            else True,
        ) as client:
            async with client.stream(
                "POST",
                url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Idempotency-Key": event_id,
                    "X-ESAA-Timestamp": timestamp,
                    "X-ESAA-Signature": signature,
                },
            ) as response:
                if (
                    response.status_code not in {200, 202}
                    or response.headers.get("X-ESAA-Accepted-Event") != event_id
                ):
                    raise RuntimeError("receiver_did_not_acknowledge_event")


def deliver(event_id: str, settings: Settings, *, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.UTC)
    factory = get_session_factory(settings)
    lease = str(uuid.uuid4())
    with factory() as session:
        row = session.scalar(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.id == event_id,
                NotificationOutbox.next_attempt_at <= now,
                NotificationOutbox.attempts < NotificationOutbox.attempt_limit,
                or_(
                    NotificationOutbox.status == "pending",
                    (NotificationOutbox.status == "processing")
                    & (NotificationOutbox.lease_until < now),
                ),
            )
            .values(
                status="processing",
                lease_token=lease,
                lease_until=now + dt.timedelta(seconds=settings.notification_timeout_seconds + 30),
                attempts=NotificationOutbox.attempts + 1,
            )
            .returning(NotificationOutbox)
        )
        if row is None:
            session.rollback()
            return False
        ticket = session.get(Ticket, row.ticket_id) if row.ticket_id else None
        cancelled = (
            ticket is None
            or ticket.severity.value != row.severity
            or ticket.status in {TicketStatus.CLOSED, TicketStatus.RESOLVED}
        )
        if not cancelled and ticket is not None and row.kind == "ack_timeout":
            parent = session.get(NotificationOutbox, row.event_key.split(":")[1])
            cancelled = parent is None or not needs_response(session, ticket, parent.created_at)
        if cancelled:
            row.status, row.lease_token, row.lease_until = "cancelled", None, None
            session.commit()
            return False
        event = {
            "event_id": row.id,
            "kind": row.kind,
            "ticket_reference": row.ticket_reference,
            "severity": row.severity,
            "resource_path": f"/?ticket={row.ticket_reference}",
            "created_at": iso_utc(row.created_at),
        }
        attempt, limit = row.attempts, row.attempt_limit
        url = (
            settings.notification_lead_webhook_url
            if row.kind == "ack_timeout"
            else settings.notification_webhook_url
        )
        session.commit()
    error = None
    try:
        if not url or len(settings.notification_signing_secret) < 32:
            raise ConfigurationError("Notification receiver is not configured.")
        asyncio.run(
            post_event(
                settings,
                url,
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode(),
                event_id,
            )
        )
    except Exception as exc:
        error = "not_configured" if isinstance(exc, ConfigurationError) else type(exc).__name__
    with factory() as session:
        updated = session.scalar(
            update(NotificationOutbox)
            .where(NotificationOutbox.id == event_id, NotificationOutbox.lease_token == lease)
            .values(
                status="delivered"
                if error is None
                else "exhausted"
                if attempt >= limit
                else "pending",
                delivered_at=now if error is None else None,
                error_code=error,
                lease_token=None,
                lease_until=None,
                next_attempt_at=now
                + dt.timedelta(
                    seconds=min(
                        300, settings.notification_retry_base_seconds * 2 ** min(attempt - 1, 10)
                    )
                ),
            )
            .returning(NotificationOutbox.id)
        )
        if updated:
            record_audit(
                session,
                action="notification.delivered" if error is None else "notification.failed",
                resource_type="notification",
                resource_id=event_id,
                detail={"attempt": attempt, "error_code": error},
            )
        session.commit()
    return error is None and bool(updated)


def drain(settings: Settings, limit: int = 50, stop: threading.Event | None = None) -> int:
    now = dt.datetime.now(dt.UTC)
    with get_session_factory(settings)() as session:
        backfill_existing(session, settings)
        discover_reminders(session, settings, now)
        session.execute(
            update(NotificationOutbox)
            .where(
                NotificationOutbox.status == "processing",
                NotificationOutbox.lease_until < now,
                NotificationOutbox.attempts >= NotificationOutbox.attempt_limit,
            )
            .values(
                status="exhausted",
                lease_token=None,
                lease_until=None,
                error_code="delivery_uncertain_after_last_attempt",
            )
        )
        session.commit()
        ids = session.scalars(
            select(NotificationOutbox.id)
            .where(
                NotificationOutbox.next_attempt_at <= now,
                NotificationOutbox.attempts < NotificationOutbox.attempt_limit,
                or_(
                    NotificationOutbox.status == "pending",
                    (NotificationOutbox.status == "processing")
                    & (NotificationOutbox.lease_until < now),
                ),
            )
            .order_by(NotificationOutbox.next_attempt_at, NotificationOutbox.id)
            .limit(limit)
        ).all()
    sent = 0
    for event_id in ids:
        if stop is not None and stop.is_set():
            break
        sent += int(deliver(event_id, settings))
    return sent


def retry(session: Session, event_id: str, settings: Settings) -> NotificationOutbox:
    row = session.get(NotificationOutbox, event_id)
    if row is None:
        raise NotFoundError()
    if row.status in {"delivered", "cancelled"}:
        return row
    if (
        row.status == "processing"
        and row.lease_until
        and aware(row.lease_until) > dt.datetime.now(dt.UTC)
    ):
        return row
    row.status, row.next_attempt_at = "pending", dt.datetime.now(dt.UTC)
    if row.attempts >= row.attempt_limit:
        row.attempt_limit += settings.notification_max_attempts
    return row


async def notification_loop(settings: Settings) -> None:
    while True:
        await asyncio.sleep(settings.notification_poll_interval_seconds)
        stop = threading.Event()
        job = asyncio.create_task(asyncio.to_thread(drain, settings, stop=stop))
        try:
            await asyncio.shield(job)
        except asyncio.CancelledError:
            stop.set()
            await job  # Finish only the current bounded delivery before closing DB pools.
            raise
        except Exception as exc:
            logger.error("notification_worker_failed error_type=%s", type(exc).__name__)
