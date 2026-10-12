"""Actual cleanup and application scheduler preserve active security budgets."""

import datetime as dt
import time

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import SecurityLimitBucket, UserSession
from app.db.session import get_engine, init_db
from app.main import create_app
from app.security.shared_limits import DatabaseLoginGuard, DatabaseWindowLimiter, SharedBudgetStore
from app.services.maintenance import maintain


def test_cleanup_preserves_live_login_leases_and_lockouts(settings):
    init_db(settings)
    store = SharedBudgetStore(get_engine(settings), "synthetic-maintenance-test-key")
    DatabaseWindowLimiter(store, "expired", limit=1, window_seconds=1, clock=lambda: 0).check(
        "synthetic-user"
    )
    guard = DatabaseLoginGuard(
        store,
        max_attempts=1,
        ip_max_attempts=4,
        window_seconds=2,
        lockout_seconds=20,
        lease_seconds=10,
        clock=lambda: 0,
    )
    guard.begin_attempt(email="inflight@example.com", ip_address="127.0.0.10")
    token = guard.begin_attempt(email="locked@example.com", ip_address="127.0.0.11")
    guard.record_failure(email="locked@example.com", ip_address="127.0.0.11", attempt_id=token)
    # The standalone request bucket and the below-threshold address failure
    # expire; the account lockout and both live reservations must remain.
    assert maintain(settings, now_epoch=5)["expired_budget_rows"] == 2
    with get_engine(settings).connect() as connection:
        states = connection.execute(select(SecurityLimitBucket)).mappings().all()
    assert any(state["locked_until"] == 20 for state in states)
    assert len(states) == 3
    assert any(event.get("state") == "inflight" for state in states for event in state["events"])


def test_old_expired_sessions_removed_and_live_session_preserved(settings):
    init_db(settings)
    now = dt.datetime.now(dt.UTC)
    from app.core.enums import Role
    from app.db.models import User

    with Session(get_engine(settings)) as session:
        user = User(
            email="retention@example.com",
            full_name="Simulated Retention",
            password_hash="synthetic-no-real-password",
            role=Role.EMPLOYEE,
        )
        session.add(user)
        session.flush()
        for key, expiration in (
            ("expired-synthetic-session", now - dt.timedelta(days=45)),
            ("live-synthetic-session", now + dt.timedelta(days=1)),
        ):
            session.add(
                UserSession(
                    jti=key,
                    user_id=user.id,
                    created_at=now - dt.timedelta(days=60),
                    expires_at=expiration,
                )
            )
        session.commit()
    assert maintain(settings)["expired_session_rows"] == 1
    with Session(get_engine(settings)) as session:
        assert session.scalars(select(UserSession.jti)).all() == ["live-synthetic-session"]


def test_running_application_scheduler_executes_cleanup(settings):
    scheduled = settings.model_copy(update={"maintenance_interval_seconds": 1})
    with TestClient(create_app(scheduled)):
        with Session(get_engine(scheduled)) as session:
            session.add(
                SecurityLimitBucket(
                    scope="expired-scheduler-test",
                    key_hash="synthetic-hash",
                    events=[],
                    locked_until=0,
                    expires_at=time.time() - 1,
                )
            )
            session.commit()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            with Session(get_engine(scheduled)) as session:
                if (
                    session.scalar(
                        select(SecurityLimitBucket).where(
                            SecurityLimitBucket.scope == "expired-scheduler-test"
                        )
                    )
                    is None
                ):
                    return
            time.sleep(0.02)
        raise AssertionError("Running application did not execute scheduled cleanup")
