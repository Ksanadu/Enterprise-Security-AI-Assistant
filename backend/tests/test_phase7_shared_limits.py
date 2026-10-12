"""Persistent budgets, atomic login admission, restart and actual worker processes."""

from concurrent.futures import ProcessPoolExecutor

import pytest
from sqlalchemy import create_engine, select

from app.core.errors import RateLimitError, SecurityControlsUnavailableError
from app.db.models import SecurityLimitBucket
from app.db.session import get_engine, init_db
from app.security.shared_limits import DatabaseLoginGuard, DatabaseWindowLimiter, SharedBudgetStore


def worker_attempt(url):
    engine = create_engine(url, connect_args={"timeout": 10})
    try:
        limiter = DatabaseWindowLimiter(
            SharedBudgetStore(engine, "synthetic-shared-test-key"), "worker-test", limit=3
        )
        try:
            limiter.check("same-user")
        except RateLimitError:
            return False
        return True
    finally:
        engine.dispose()


def shared(settings):
    init_db(settings)
    return SharedBudgetStore(get_engine(settings), "synthetic-shared-test-key")


def guard(store, clock):
    return DatabaseLoginGuard(
        store,
        max_attempts=2,
        ip_max_attempts=4,
        window_seconds=5,
        lockout_seconds=20,
        lease_seconds=10,
        clock=clock,
    )


def test_actual_worker_processes_share_one_budget(settings):
    shared(settings)
    with ProcessPoolExecutor(max_workers=3) as executor:
        permitted = list(executor.map(worker_attempt, [settings.database_url] * 12))
    assert sum(permitted) == 3


def test_recreated_limiter_and_scopes_preserve_budget(settings):
    store = shared(settings)
    first = DatabaseWindowLimiter(store, "chat", limit=1)
    first.check("same-user")
    restarted = DatabaseWindowLimiter(
        SharedBudgetStore(get_engine(settings), "synthetic-shared-test-key"), "chat", limit=1
    )
    with pytest.raises(RateLimitError):
        restarted.check("same-user")
    DatabaseWindowLimiter(store, "search", limit=1).check("same-user")


def test_login_inflight_slots_do_not_amplify_across_instances(settings):
    store, now = shared(settings), [0.0]
    one, two = guard(store, lambda: now[0]), guard(store, lambda: now[0])
    one.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
    two.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.11")
    with pytest.raises(RateLimitError):
        two.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.12")
    now[0] = 6  # Window expired, but the live reservations must still hold.
    assert one.is_locked(email="synthetic@example.com", ip_address="127.0.0.13")
    now[0] = 11  # A crashed caller's expired lease can be reclaimed.
    assert not two.is_locked(email="synthetic@example.com", ip_address="127.0.0.13")


def test_lockout_survives_restart_and_outlasts_failure_window(settings):
    store, now = shared(settings), [0.0]
    one = guard(store, lambda: now[0])
    for _ in range(2):
        token = one.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
        one.record_failure(email="synthetic@example.com", ip_address="127.0.0.10", attempt_id=token)
    two = guard(store, lambda: now[0])
    now[0] = 6
    assert two.is_locked(email="SYNTHETIC@example.com", ip_address="127.0.0.11")
    now[0] = 21
    assert not two.is_locked(email="synthetic@example.com", ip_address="127.0.0.11")


def test_success_preserves_other_inflight_slots_and_address_failures(settings):
    store, now = shared(settings), [0.0]
    instance = guard(store, lambda: now[0])
    failed = instance.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
    instance.record_failure(
        email="synthetic@example.com", ip_address="127.0.0.10", attempt_id=failed
    )
    success = instance.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
    instance.record_success(
        email="synthetic@example.com", ip_address="127.0.0.10", attempt_id=success
    )
    with get_engine(settings).connect() as connection:
        records = connection.execute(select(SecurityLimitBucket)).mappings().all()
    assert next(row for row in records if row["scope"] == "login_account")["events"] == []
    assert len(next(row for row in records if row["scope"] == "login_address")["events"]) == 1
    assert "synthetic@example.com" not in repr(records) and "127.0.0.10" not in repr(records)
    first = instance.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
    second = instance.begin_attempt(email="synthetic@example.com", ip_address="127.0.0.10")
    instance.record_success(
        email="synthetic@example.com", ip_address="127.0.0.10", attempt_id=first
    )
    with get_engine(settings).connect() as connection:
        account = connection.execute(
            select(SecurityLimitBucket.events).where(SecurityLimitBucket.scope == "login_account")
        ).scalar()
    assert [event["id"] for event in account] == [second]


def test_missing_shared_store_refuses_request_and_readiness(client, settings):
    with get_engine(settings).begin() as connection:
        connection.exec_driver_sql("DROP TABLE security_limit_buckets")
    response = client.post(
        "/api/v1/auth/login", json={"email": "employee@example.com", "password": "Demo@12345"}
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "security_controls_unavailable"
    assert client.get("/api/v1/ready").status_code == 503


def test_limiter_storage_failure_does_not_fall_back_to_memory(settings):
    store = shared(settings)
    with get_engine(settings).begin() as connection:
        connection.exec_driver_sql("DROP TABLE security_limit_buckets")
    with pytest.raises(SecurityControlsUnavailableError):
        DatabaseWindowLimiter(store, "chat", limit=1).check("same-user")
