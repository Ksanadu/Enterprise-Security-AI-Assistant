"""Real database gauges and an external patrol through an actual loopback API."""

import datetime as dt
import importlib.util
import json
import logging
import socket
import threading
import time
from pathlib import Path

import httpx
import uvicorn
from sqlalchemy import select

from app.core.enums import Severity
from app.core.logging import JsonFormatter
from app.db.models import AuditLog, NotificationOutbox, TicketEvent, WorkflowTask
from app.db.session import get_session_factory, init_db
from app.main import create_app
from app.services.operations_status import snapshot
from app.services.ticket_service import TicketService


def test_aggregate_gauges_are_private_and_respect_human_response_time(settings):
    init_db(settings)
    settings.notification_webhook_url = "https://synthetic-receiver.invalid"
    now = dt.datetime.now(dt.UTC)
    old = now - dt.timedelta(hours=2)
    with get_session_factory(settings)() as session:
        ticket = TicketService().create_ticket(
            session,
            title="Synthetic private title",
            description="Synthetic private body",
            severity=Severity.HIGH,
        )
        alert = session.scalar(select(NotificationOutbox))
        alert.created_at = old
        ticket.created_at = old
        for event in session.scalars(select(TicketEvent).where(TicketEvent.ticket_id == ticket.id)):
            event.created_at = old
        # An automated status or a response BEFORE the escalation cannot silence an alert.
        session.add_all(
            [
                TicketEvent(
                    ticket_id=ticket.id,
                    created_at=old - dt.timedelta(seconds=1),
                    event_type="note",
                    actor_role="security",
                    automated=False,
                ),
                TicketEvent(
                    ticket_id=ticket.id,
                    created_at=now,
                    event_type="status_changed",
                    actor_role="security",
                    automated=True,
                ),
                WorkflowTask(id="synthetic-work", status="pending", snapshot={}, created_at=old),
                AuditLog(
                    action="chat.query.answered",
                    created_at=now,
                    detail={"model_usage": {"failures": 2, "budget_exhausted": True}},
                ),
                AuditLog(
                    action="chat.query.answered",
                    created_at=old,
                    detail={"model_usage": {"failures": 90}},
                ),
                AuditLog(action="workflow.failed", created_at=now),
            ]
        )
        session.commit()
        result = snapshot(session, settings, knowledge_ready=False, now=now)
        assert result["response_overdue"] == {"high": 1, "critical": 0}
        assert result["model"] == {"recent_network_failures": 2, "recent_budget_exhaustions": 1}
        assert result["workflow"]["stale_count"] == 1
        assert result["notifications"]["stale_count"] == 1
        assert {
            "knowledge_unavailable",
            "high_risk_response_overdue",
            "workflow_failures_last_hour",
        } <= set(result["alerts"])
        assert "Synthetic private" not in json.dumps(result) and ticket.reference not in json.dumps(
            result
        )
        session.add(
            TicketEvent(
                ticket_id=ticket.id,
                created_at=now,
                event_type="note",
                actor_role="it",
                automated=False,
            )
        )
        session.commit()
        assert (
            snapshot(session, settings, knowledge_ready=True, now=now)["response_overdue"]["high"]
            == 0
        )
        alert.status = "exhausted"
        session.commit()
        assert (
            "notification_retry_exhausted"
            in snapshot(session, settings, knowledge_ready=True)["alerts"]
        )


def test_empty_gauges_and_expired_leases_are_not_reported_as_healthy_queue(settings):
    init_db(settings)
    with get_session_factory(settings)() as session:
        result = snapshot(session, settings, knowledge_ready=True)
        assert result["alerts"] == ["notification_receiver_unconfigured"]
        assert result["workflow"]["by_status"] == {}
        assert result["model"]["recent_network_failures"] == 0
        # Actual unrecovered processing work remains visible after a restart.
        session.add(
            WorkflowTask(
                id="synthetic-expired",
                status="processing",
                snapshot={},
                created_at=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=6),
            )
        )
        session.commit()
        assert (
            "workflow_backlog_over_5m"
            in snapshot(session, settings, knowledge_ready=True)["alerts"]
        )


def test_operations_status_requires_security_role(
    client, employee_headers, it_headers, security_headers
):
    assert client.get("/api/v1/operations/status").status_code == 401
    for headers in (employee_headers, it_headers):
        assert client.get("/api/v1/operations/status", headers=headers).status_code == 403
    response = client.get("/api/v1/operations/status", headers=security_headers)
    assert response.status_code == 200 and "alerts" in response.json()


def monitor_module():
    spec = importlib.util.spec_from_file_location(
        "esaa_ops_monitor", Path(__file__).resolve().parents[2] / "scripts" / "ops-monitor.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_external_patrol_uses_actual_api_and_revokes_its_session(settings):
    module = monitor_module()
    assert module.patrol("https://user:synthetic-secret@example.invalid", "a", "b")[1] == 2
    assert module.patrol("http://example.invalid", "a", "b")[1] == 2
    assert module.patrol("http://127.0.0.1", "", "")[1] == 2
    settings.log_level = "INFO"
    app = create_app(settings)
    # Pass an already bound socket to uvicorn, avoiding port allocation races.
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    base = f"http://127.0.0.1:{listener.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(app, log_config=None))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = Capture()
    access = logging.getLogger("app.http")
    access.addHandler(handler)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and thread.is_alive() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert server.started
        result, code = module.patrol(base, "security@example.com", "Demo@12345")
        assert code == 1 and "notification_receiver_unconfigured" in result["alerts"]
        denied, code = module.patrol(base, "employee@example.com", "Demo@12345")
        assert code == 2 and denied["alerts"] == ["monitor_probe_failed"]
        from app.db.models import UserSession

        with get_session_factory(settings)() as session:
            assert all(row.revoked_at is not None for row in session.scalars(select(UserSession)))
        # Input text and identifiers never become log route labels.
        with httpx.Client(trust_env=False) as client:
            client.get(
                base + "/synthetic-private-path?token=synthetic-private-query",
                headers={"X-Request-ID": "patrol-correlation"},
            )
        record = next(
            row for row in records if getattr(row, "request_id", None) == "patrol-correlation"
        )
        formatted = json.loads(JsonFormatter().format(record))
        assert (
            formatted["request_id"] == "patrol-correlation" and formatted["route"] == "<unmatched>"
        )
        assert formatted["status"] == 404 and formatted["duration_ms"] >= 0
        assert "synthetic-private" not in json.dumps(formatted)
    finally:
        server.should_exit = True
        thread.join(timeout=20)
        listener.close()
        access.removeHandler(handler)
        assert not thread.is_alive()
