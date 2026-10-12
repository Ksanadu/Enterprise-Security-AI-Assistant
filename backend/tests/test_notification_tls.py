"""Certificate validation and actual production scheduler use a real local TLS receiver."""

import datetime as dt
import sqlite3
import time
from contextlib import closing

from fastapi.testclient import TestClient
from scripts.notification_test_receiver import receiver
from sqlalchemy import select

from app.core.enums import Severity
from app.db.models import NotificationOutbox
from app.db.session import get_session_factory, init_db
from app.main import create_app
from app.services.notifications import aware, deliver
from app.services.ticket_service import TicketService


def test_tls_rejects_untrusted_certificate_then_accepts_configured_ca(settings, tmp_path):
    secret = "synthetic-long-notification-signing-secret"
    with receiver(tmp_path / "tls-receiver", secret) as endpoint:
        settings.notification_webhook_url = endpoint["primary_url"]
        settings.notification_lead_webhook_url = endpoint["lead_url"]
        settings.notification_signing_secret = secret
        settings.notification_poll_interval_seconds = 0
        init_db(settings)
        with get_session_factory(settings)() as session:
            TicketService().create_ticket(
                session, title="Synthetic TLS incident", severity=Severity.HIGH
            )
            session.commit()
            row = session.scalar(select(NotificationOutbox))
            event_id, created = row.id, aware(row.created_at)
        assert not deliver(event_id, settings, now=created + dt.timedelta(seconds=1))
        assert endpoint["requests"] == 0
        settings.notification_ca_bundle_file = endpoint["ca_file"]
        assert deliver(event_id, settings, now=created + dt.timedelta(seconds=10))
        assert endpoint["requests"] == 1 and endpoint["signature_errors"] == 0


def test_production_worker_delivers_over_tls_and_escalates_unacknowledged_incident(
    settings, tmp_path
):
    secret = "synthetic-production-notification-signing-secret"
    with receiver(tmp_path / "production-receiver", secret) as endpoint:
        settings.notification_webhook_url = endpoint["primary_url"]
        settings.notification_lead_webhook_url = endpoint["lead_url"]
        settings.notification_signing_secret = secret
        settings.notification_ca_bundle_file = endpoint["ca_file"]
        settings.notification_poll_interval_seconds = 1
        settings.notification_critical_ack_seconds = 1
        settings.workflow_retry_interval_seconds = 1
        settings.maintenance_interval_seconds = 1
        init_db(settings)
        with get_session_factory(settings)() as session:
            TicketService().create_ticket(
                session,
                title="Synthetic production critical",
                severity=Severity.CRITICAL,
                escalation_required=True,
            )
            session.commit()
        production = settings.model_copy(
            update={
                "app_env": "production",
                "seed_demo_users": False,
                "allow_demo_login": False,
                "debug": False,
            }
        )
        with TestClient(create_app(production)):
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline:
                with closing(sqlite3.connect(endpoint["database"])) as connection:
                    channels = {
                        row[0] for row in connection.execute("SELECT channel FROM receipts")
                    }
                if channels == {"/primary", "/lead"}:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "Actual production worker did not deliver alert and timeout reminder"
                )
        assert endpoint["signature_errors"] == 0
