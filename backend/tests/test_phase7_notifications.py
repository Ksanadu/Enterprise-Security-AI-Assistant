"""Real loopback receiver verifies signing, failure recovery, dedupe and human response."""

import datetime as dt
import hashlib
import hmac
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from sqlalchemy import select

from app.core.enums import Role, Severity, TicketStatus
from app.db.models import NotificationOutbox, Ticket, TicketEvent
from app.db.session import get_session_factory, init_db
from app.services.notifications import aware, deliver, discover_reminders, enqueue
from app.services.ticket_service import TicketService


@pytest.fixture
def receiver(settings):
    state = {
        "fail": False,
        "accepted": {},
        "requests": [],
        "bad_signature": False,
        "wrong_ack": False,
    }
    settings.notification_signing_secret = "synthetic-notification-signing-secret-no-real-key"
    settings.notification_timeout_seconds = 1
    settings.notification_poll_interval_seconds = 0
    settings.notification_high_ack_seconds = 1
    settings.notification_critical_ack_seconds = 1

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):  # noqa: N802 -- required stdlib HTTP handler hook
            body = self.rfile.read(int(self.headers["Content-Length"]))
            signed = self.headers["X-ESAA-Timestamp"].encode() + b"." + body
            expected = hmac.new(
                settings.notification_signing_secret.encode(), signed, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, self.headers["X-ESAA-Signature"]):
                state["bad_signature"] = True
                self.send_response(403)
                self.end_headers()
                return
            event = json.loads(body)
            if state.get("slow_headers"):
                time.sleep(2)
            state["requests"].append(event)
            if state["fail"]:
                self.send_response(503)
            else:
                state["accepted"].setdefault(event["event_id"], event)
                self.send_response(202)
                self.send_header(
                    "X-ESAA-Accepted-Event", "wrong-id" if state["wrong_ack"] else event["event_id"]
                )
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    settings.notification_webhook_url = f"http://127.0.0.1:{server.server_port}/primary"
    settings.notification_lead_webhook_url = f"http://127.0.0.1:{server.server_port}/lead"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def create_alert(settings):
    init_db(settings)
    with get_session_factory(settings)() as session:
        ticket = TicketService().create_ticket(
            session,
            title="Synthetic private report",
            description="simulated body must never leave API",
            severity=Severity.HIGH,
            escalation_required=True,
        )
        enqueue(session, ticket)
        session.commit()
        row = session.scalar(select(NotificationOutbox))
        return ticket.id, row.id, aware(row.created_at)


def test_receiver_failure_retry_preserves_ticket_and_minimizes_data(settings, receiver):
    ticket_id, event_id, created = create_alert(settings)
    receiver["fail"] = True
    assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        assert row.status == "pending" and row.attempts == 1 and row.ticket_id == ticket_id
    receiver["fail"] = False
    assert deliver(event_id, settings, now=created + dt.timedelta(seconds=10))
    assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=20))
    assert len(receiver["accepted"]) == 1 and not receiver["bad_signature"]
    assert set(receiver["requests"][0]) == {
        "event_id",
        "kind",
        "ticket_reference",
        "severity",
        "resource_path",
        "created_at",
    }
    assert "private report" not in repr(receiver["requests"]) and "simulated body" not in repr(
        receiver["requests"]
    )


def test_missing_receiver_ack_is_not_marked_delivered(settings, receiver):
    _, event_id, created = create_alert(settings)
    receiver["wrong_ack"] = True
    assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
    with get_session_factory(settings)() as session:
        assert session.get(NotificationOutbox, event_id).delivered_at is None


def test_atomic_enqueue_rolls_back_with_ticket(settings):
    init_db(settings)
    with get_session_factory(settings)() as session:
        ticket = TicketService().create_ticket(
            session, title="Synthetic rollback", severity=Severity.HIGH
        )
        ticket_id = ticket.id
        session.rollback()
    with get_session_factory(settings)() as session:
        assert (
            session.scalar(
                select(NotificationOutbox).where(NotificationOutbox.ticket_id == ticket_id)
            )
            is None
        )


def test_ack_timeout_deduplicates_and_human_response_cancels_reminder(settings, receiver):
    ticket_id, event_id, created = create_alert(settings)
    with get_session_factory(settings)() as session:
        discover_reminders(session, settings, created + dt.timedelta(seconds=2))
        discover_reminders(session, settings, created + dt.timedelta(seconds=2))
        session.commit()
        reminders = session.scalars(
            select(NotificationOutbox).where(NotificationOutbox.kind == "ack_timeout")
        ).all()
        assert len(reminders) == 1
        reminder_id = reminders[0].id
        session.add(
            TicketEvent(
                ticket_id=ticket_id,
                created_at=created + dt.timedelta(seconds=3),
                event_type="note",
                actor_role=Role.SECURITY.value,
                automated=False,
                note="Synthetic human acknowledgment",
            )
        )
        session.commit()
    assert not deliver(reminder_id, settings, now=created + dt.timedelta(seconds=4))
    assert receiver["requests"] == []
    with get_session_factory(settings)() as session:
        assert session.get(NotificationOutbox, reminder_id).status == "cancelled"


def test_crash_after_receiver_acceptance_retries_same_event_without_second_effect(
    settings, receiver, monkeypatch
):
    import app.services.notifications as notification_module

    _, event_id, created = create_alert(settings)
    real_factory = get_session_factory(settings)
    calls = [0]

    @contextmanager
    def crashing_session():
        calls[0] += 1
        if calls[0] == 2:
            raise RuntimeError("synthetic process failure before recording delivery")
        with real_factory() as session:
            yield session

    monkeypatch.setattr(
        notification_module, "get_session_factory", lambda _settings: crashing_session
    )
    with pytest.raises(RuntimeError, match="synthetic process failure"):
        deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
    monkeypatch.setattr(notification_module, "get_session_factory", lambda _settings: real_factory)
    assert deliver(event_id, settings, now=created + dt.timedelta(seconds=60))
    assert len(receiver["requests"]) == 2 and len(receiver["accepted"]) == 1


def test_concurrent_delivery_claims_one_event(settings, receiver):
    _, event_id, created = create_alert(settings)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: deliver(event_id, settings, now=created + dt.timedelta(seconds=1)),
                range(2),
            )
        )
    assert sum(results) == 1 and len(receiver["requests"]) == 1


def test_receiver_timeout_is_bounded_and_recorded(settings, receiver):
    _, event_id, created = create_alert(settings)
    receiver["slow_headers"] = True
    started = time.monotonic()
    assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
    assert time.monotonic() - started < 1.8
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        assert row.status == "pending" and row.delivered_at is None


def test_retry_exhaustion_requires_authorized_new_budget(settings, receiver):
    from app.services.notifications import retry

    _, event_id, created = create_alert(settings)
    with get_session_factory(settings)() as session:
        session.get(NotificationOutbox, event_id).attempt_limit = 1
        session.commit()
    receiver["fail"] = True
    assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        assert row.status == "exhausted" and row.attempts == 1
        retry(session, event_id, settings)
        session.commit()
    receiver["fail"] = False
    assert deliver(event_id, settings, now=created + dt.timedelta(seconds=10))


def test_reminder_batches_do_not_starve_later_incidents(settings):
    init_db(settings)
    settings.notification_high_ack_seconds = 1
    created = dt.datetime.now(dt.UTC)
    with get_session_factory(settings)() as session:
        tickets = [
            Ticket(
                reference=f"SEC-SYNTHETIC-BATCH-{index}",
                title="Synthetic batch",
                severity=Severity.HIGH,
            )
            for index in range(501)
        ]
        session.add_all(tickets)
        session.flush()
        for ticket in tickets:
            enqueue(session, ticket, now=created)
        session.commit()
        now = created + dt.timedelta(seconds=2)
        assert discover_reminders(session, settings, now) == 500
        session.commit()
        assert discover_reminders(session, settings, now) == 1
        session.commit()
        assert (
            len(
                session.scalars(
                    select(NotificationOutbox).where(NotificationOutbox.kind == "ack_timeout")
                ).all()
            )
            == 501
        )


def test_expired_last_attempt_is_uncertain_and_does_not_block_queue(settings):
    from app.services.notifications import drain

    _, event_id, created = create_alert(settings)
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        row.status, row.attempts, row.attempt_limit = "processing", 1, 1
        row.lease_until = created - dt.timedelta(seconds=1)
        session.commit()
    assert drain(settings) == 0
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        assert (
            row.status == "exhausted" and row.error_code == "delivery_uncertain_after_last_attempt"
        )


def test_notification_endpoints_are_security_only(
    client, employee_headers, it_headers, security_headers
):
    assert (
        client.get("/api/v1/operations/notifications", headers=employee_headers).status_code == 403
    )
    assert client.get("/api/v1/operations/notifications", headers=it_headers).status_code == 403
    assert (
        client.get("/api/v1/operations/notifications", headers=security_headers).status_code == 200
    )


def test_retry_api_enforces_permission_and_only_requeues(
    settings, client, employee_headers, it_headers, security_headers
):
    from app.db.models import AuditLog

    with get_session_factory(settings)() as session:
        TicketService().create_ticket(
            session, title="Synthetic retry API event", severity=Severity.HIGH
        )
        session.flush()
        row = session.scalar(select(NotificationOutbox))
        row.status, row.attempts, row.attempt_limit = "exhausted", 1, 1
        event_id = row.id
        session.commit()
    path = f"/api/v1/operations/notifications/{event_id}/retry"
    assert client.post(path).status_code == 401
    for headers in (employee_headers, it_headers):
        assert client.post(path, headers=headers).status_code == 403
    with get_session_factory(settings)() as session:
        assert session.get(NotificationOutbox, event_id).status == "exhausted"
    response = client.post(path, headers=security_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "pending" and response.json()["attempts"] == 1
    assert response.json()["delivered_at"] is None
    with get_session_factory(settings)() as session:
        row = session.get(NotificationOutbox, event_id)
        assert row.attempt_limit == 1 + settings.notification_max_attempts
        audit = session.scalar(
            select(AuditLog).where(AuditLog.action == "notification.retry_requested")
        )
        assert audit.actor_role == "security" and audit.resource_id == event_id
        row.status = "delivered"
        session.commit()
    assert client.post(path, headers=security_headers).json()["status"] == "delivered"
    assert (
        client.post(
            "/api/v1/operations/notifications/missing-event/retry", headers=security_headers
        ).status_code
        == 404
    )


def test_shutdown_stop_finishes_current_delivery_and_preserves_the_rest(
    settings, receiver, monkeypatch
):
    from app.services import notifications

    create_alert(settings)
    with get_session_factory(settings)() as session:
        TicketService().create_ticket(
            session, title="Second synthetic event", severity=Severity.HIGH
        )
        session.commit()
    stop = threading.Event()
    original = notifications.deliver

    def finish_one(event_id, config):
        result = original(event_id, config)
        stop.set()
        return result

    monkeypatch.setattr(notifications, "deliver", finish_one)
    assert notifications.drain(settings, stop=stop) == 1
    assert len(receiver["requests"]) == 1
    with get_session_factory(settings)() as session:
        assert sorted(session.scalars(select(NotificationOutbox.status))) == [
            "delivered",
            "pending",
        ]


def test_retained_incidents_are_reconciled_sent_and_observed_without_false_ack(settings, receiver):
    from app.services.notifications import drain
    from app.services.operations_status import snapshot

    init_db(settings)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(hours=2)
    with get_session_factory(settings)() as session:
        legacy = Ticket(
            reference="SEC-SYNTHETIC-LEGACY",
            title="Retained synthetic High",
            severity=Severity.HIGH,
            status=TicketStatus.ESCALATED,
            created_at=old,
        )
        acknowledged = Ticket(
            reference="SEC-SYNTHETIC-ACK",
            title="Already acknowledged",
            severity=Severity.HIGH,
            status=TicketStatus.IN_PROGRESS,
            created_at=old,
        )
        terminal = Ticket(
            reference="SEC-SYNTHETIC-TERMINAL",
            title="Already resolved",
            severity=Severity.HIGH,
            status=TicketStatus.RESOLVED,
            created_at=old,
        )
        raised = Ticket(
            reference="SEC-SYNTHETIC-RAISED",
            title="Escalated after prior response",
            severity=Severity.CRITICAL,
            status=TicketStatus.ESCALATED,
            created_at=old,
        )
        session.add_all([legacy, acknowledged, terminal, raised])
        session.flush()
        session.add_all(
            [
                TicketEvent(
                    ticket_id=acknowledged.id,
                    created_at=old + dt.timedelta(seconds=1),
                    event_type="note",
                    actor_role="security",
                    automated=False,
                ),
                TicketEvent(
                    ticket_id=raised.id,
                    created_at=old + dt.timedelta(seconds=1),
                    event_type="note",
                    actor_role="it",
                    automated=False,
                ),
                TicketEvent(
                    ticket_id=raised.id,
                    created_at=old + dt.timedelta(minutes=30),
                    event_type="severity_changed",
                    to_severity="critical",
                    automated=True,
                ),
            ]
        )
        session.commit()
        before = snapshot(session, settings, knowledge_ready=True)
        assert before["response_overdue"] == {"high": 1, "critical": 1}
        assert before["notifications"]["missing_incident_count"] == 2
        assert "high_risk_notification_missing" in before["alerts"]
    assert drain(settings) == 4
    assert drain(settings) == 0
    assert sorted(event["kind"] for event in receiver["requests"]) == [
        "ack_timeout",
        "ack_timeout",
        "incident",
        "incident",
    ]
    assert {event["ticket_reference"] for event in receiver["requests"]} == {
        legacy.reference,
        raised.reference,
    }
    with get_session_factory(settings)() as session:
        assert (
            session.scalar(
                select(NotificationOutbox.status).where(
                    NotificationOutbox.ticket_id == acknowledged.id
                )
            )
            == "cancelled"
        )
        assert (
            session.scalar(
                select(NotificationOutbox.id).where(NotificationOutbox.ticket_id == terminal.id)
            )
            is None
        )
        after = snapshot(session, settings, knowledge_ready=True)
        assert after["notifications"]["missing_incident_count"] == 0
        assert after["response_overdue"] == {"high": 1, "critical": 1}
        assert "high_risk_notification_missing" not in after["alerts"]


def test_retained_reconciliation_batches_progress_and_keep_unique_events(settings):
    from app.services.notifications import backfill_existing

    init_db(settings)
    with get_session_factory(settings)() as session:
        session.add_all(
            Ticket(
                reference=f"SEC-SYNTHETIC-RECON-{i}", title="Retained batch", severity=Severity.HIGH
            )
            for i in range(3)
        )
        session.commit()
        assert backfill_existing(session, settings, limit=2) == 2
        session.commit()
        assert backfill_existing(session, settings, limit=2) == 1
        session.commit()
        assert backfill_existing(session, settings, limit=2) == 0
        assert len(session.scalars(select(NotificationOutbox)).all()) == 3
