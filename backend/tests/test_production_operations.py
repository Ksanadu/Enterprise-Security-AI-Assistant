"""Production safeguards use actual retained users and sanitize config errors."""

import datetime as dt
import traceback

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.enums import Role
from app.core.errors import ConfigurationError
from app.db.models import Ticket, User, UserSession
from app.db.session import get_session_factory, init_db
from app.security.production_checks import check_production, validate_notification_configuration


def production(settings):
    return settings.model_copy(
        update={
            "app_env": "production",
            "notification_webhook_url": "https://127.0.0.1:1/primary",
            "notification_lead_webhook_url": "https://127.0.0.1:1/lead",
            "notification_signing_secret": "synthetic-signing-key-long-enough-for-test",
            "notification_poll_interval_seconds": 30,
            "workflow_retry_interval_seconds": 30,
        }
    )


def test_retained_prototype_accounts_refuse_production_without_deleting_them(settings):
    init_db(settings)
    with get_session_factory(settings)() as session:
        session.add(
            User(
                email="employee@example.com",
                full_name="Retained synthetic prototype",
                password_hash="synthetic-hash",
                role=Role.EMPLOYEE,
            )
        )
        session.commit()
    with pytest.raises(RuntimeError, match="prototype accounts"):
        check_production(production(settings))
    with get_session_factory(settings)() as session:
        user = session.scalar(select(User))
        assert user.is_active
        user.is_active = False
        session.commit()
    check_production(production(settings))


def test_missing_receiver_and_plain_http_refused_in_production(settings):
    value = production(settings)
    value.notification_webhook_url = ""
    with pytest.raises(RuntimeError, match="configured notification"):
        validate_notification_configuration(value)
    value.notification_webhook_url = "http://127.0.0.1:1/primary"
    with pytest.raises(RuntimeError, match="HTTPS"):
        validate_notification_configuration(value)


def test_production_cannot_disable_workflow_recovery(settings):
    from pydantic import ValidationError

    from app.core.config import Settings

    values = settings.model_dump()
    values.update(
        app_env="production",
        debug=False,
        seed_demo_users=False,
        allow_demo_login=False,
        demo_user_password="SyntheticUnusedPassword#2026",
        password_hash_rounds=12,
        api_cors_origins=["https://synthetic-pilot.invalid"],
        workflow_retry_interval_seconds=0,
    )
    with pytest.raises(ValidationError, match="requires workflow recovery"):
        Settings(**values)


def test_config_traceback_does_not_echo_environment_secrets(monkeypatch):
    marker = "synthetic-private-key-must-not-be-printed-2026"
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("AUTH_SECRET_KEY", marker)
    monkeypatch.setenv("ALLOW_DEMO_LOGIN", "true")
    get_settings.cache_clear()
    try:
        with pytest.raises(ConfigurationError) as captured:
            get_settings()
        rendered = "".join(traceback.format_exception(captured.value))
        assert marker not in rendered
    finally:
        get_settings.cache_clear()


def test_retirement_dry_run_backup_revocation_and_history_preservation(settings, tmp_path):
    from scripts.retire_prototype_users import retire

    init_db(settings)
    with get_session_factory(settings)() as session:
        demo = User(
            email="employee@example.com",
            full_name="Synthetic old demo",
            password_hash="synthetic-hash",
            role=Role.EMPLOYEE,
        )
        normal = User(
            email="realistic-synthetic@example.com",
            full_name="Synthetic retained principal",
            password_hash="synthetic-hash",
            role=Role.EMPLOYEE,
        )
        session.add_all([demo, normal])
        session.flush()
        now = dt.datetime.now(dt.UTC)
        session.add(
            UserSession(
                jti="synthetic-prototype-session",
                user_id=demo.id,
                created_at=now,
                expires_at=now + dt.timedelta(days=1),
            )
        )
        session.add(
            Ticket(
                reference="REQ-SYNTHETIC-RETIRE",
                title="Retained synthetic history",
                created_by_user_id=demo.id,
            )
        )
        session.commit()
    assert retire(apply=False, backup_path=None)["active_prototype_accounts"] == 1
    with get_session_factory(settings)() as session:
        assert session.scalar(select(User).where(User.email == "employee@example.com")).is_active
    backup = tmp_path / "before-retirement.db"
    assert retire(apply=True, backup_path=backup)["backup_verified"]
    assert backup.exists() and backup.with_name(backup.name + ".manifest.json").exists()
    with get_session_factory(settings)() as session:
        assert not session.scalar(
            select(User).where(User.email == "employee@example.com")
        ).is_active
        assert session.scalar(
            select(User).where(User.email == "realistic-synthetic@example.com")
        ).is_active
        assert session.scalar(select(UserSession)).revoked_at is not None
        assert session.scalar(select(Ticket)).title == "Retained synthetic history"
