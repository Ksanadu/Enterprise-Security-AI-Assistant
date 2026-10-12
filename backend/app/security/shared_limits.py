"""SQLite pilot budgets with short atomic writes and leased login admission.

Limits are shared across workers and persist across restart. A failed store
refuses requests with 503; it never silently switches to process-local budgets.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, cast

from sqlalchemy import Connection, Engine, Table, delete, select
from sqlalchemy.dialects.sqlite import insert
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import RateLimitError, SecurityControlsUnavailableError
from app.db.models import SecurityLimitBucket
from app.security.login_guard import LOCKOUT_MESSAGE, LoginGuard
from app.security.rate_limit import SlidingWindowLimiter

TABLE = cast(Table, SecurityLimitBucket.__table__)


class SharedBudgetStore:
    def __init__(self, engine: Engine, secret: str) -> None:
        if engine.dialect.name != "sqlite":
            raise RuntimeError("Shared limits currently require the accepted SQLite pilot backend.")
        self.engine = engine
        self.secret = secret.encode()

    def key(self, scope: str, value: str) -> str:
        return hmac.new(self.secret, (scope + ":" + value).encode(), hashlib.sha256).hexdigest()

    @contextmanager
    def atomic(self) -> Iterator[Connection]:
        try:
            with self.engine.connect() as connection, connection.begin():
                connection.exec_driver_sql("BEGIN IMMEDIATE")
                yield connection
        except (SQLAlchemyError, ValueError, TypeError) as exc:
            raise SecurityControlsUnavailableError() from exc

    def read(self, connection: Connection, scope: str, key: str) -> dict[str, Any]:
        row = (
            connection.execute(select(TABLE).where(TABLE.c.scope == scope, TABLE.c.key_hash == key))
            .mappings()
            .first()
        )
        return dict(row) if row else {"events": [], "locked_until": 0.0}

    def write(
        self, connection: Connection, scope: str, key: str, state: dict[str, Any], expires: float
    ) -> None:
        expires = max(
            [expires, state["locked_until"]]
            + [
                event["lease"]
                for event in state["events"]
                if isinstance(event, dict) and event.get("state") == "inflight"
            ]
        )
        values = {
            "scope": scope,
            "key_hash": key,
            "events": state["events"],
            "locked_until": state["locked_until"],
            "expires_at": expires,
        }
        statement = insert(TABLE).values(**values)
        connection.execute(
            statement.on_conflict_do_update(
                index_elements=[TABLE.c.scope, TABLE.c.key_hash],
                set_={
                    name: value
                    for name, value in values.items()
                    if name not in {"scope", "key_hash"}
                },
            )
        )


class DatabaseWindowLimiter(SlidingWindowLimiter):
    def __init__(
        self,
        store: SharedBudgetStore,
        scope: str,
        *,
        limit: int,
        window_seconds: float = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if limit < 1 or window_seconds <= 0:
            raise ValueError("Positive limit/window required")
        self.store, self.scope = store, scope
        self._limit, self._window, self._clock = limit, window_seconds, clock

    def _live_events(self, state: dict, now: float) -> list[float]:
        return [event for event in state["events"] if event > now - self._window]

    def check(self, key: str) -> None:
        hashed = self.store.key(self.scope, key)
        with self.store.atomic() as connection:
            now = self._clock()
            state = self.store.read(connection, self.scope, hashed)
            events = self._live_events(state, now)
            if len(events) >= self._limit:
                raise RateLimitError(
                    details={
                        "retry_after_seconds": max(1, math.ceil(events[0] + self._window - now)),
                        "limit": self._limit,
                    }
                )
            state["events"] = [*events, now]
            self.store.write(connection, self.scope, hashed, state, now + self._window)

    def remaining(self, key: str) -> int:
        hashed = self.store.key(self.scope, key)
        with self.store.atomic() as connection:
            return max(
                0,
                self._limit
                - len(
                    self._live_events(
                        self.store.read(connection, self.scope, hashed), self._clock()
                    )
                ),
            )

    def reset(self, key: str | None = None) -> None:
        with self.store.atomic() as connection:
            statement = delete(TABLE).where(TABLE.c.scope == self.scope)
            if key is not None:
                statement = statement.where(TABLE.c.key_hash == self.store.key(self.scope, key))
            connection.execute(statement)


class DatabaseLoginGuard(LoginGuard):
    def __init__(
        self,
        store: SharedBudgetStore,
        *,
        max_attempts: int,
        ip_max_attempts: int,
        window_seconds: float,
        lockout_seconds: float,
        lease_seconds: float = 30,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if min(max_attempts, ip_max_attempts, window_seconds, lockout_seconds, lease_seconds) <= 0:
            raise ValueError("Positive login budgets required")
        self.store = store
        self._max_attempts, self._ip_max_attempts = max_attempts, ip_max_attempts
        self._window, self._lockout_seconds = window_seconds, lockout_seconds
        self.lease_seconds, self.clock = lease_seconds, clock

    def _keys(self, email: str, address: str | None):
        return (
            ("login_account", self._account_key(email), self._max_attempts),
            ("login_address", self._address_key(address), self._ip_max_attempts),
        )

    def _state(self, connection: Connection, scope: str, value: str, now: float):
        key = self.store.key(scope, value)
        state = self.store.read(connection, scope, key)
        state["events"] = [
            event
            for event in state["events"]
            if (
                event["lease"] > now
                if event["state"] == "inflight"
                else event["at"] > now - self._window
            )
        ]
        return key, state

    def is_locked(self, *, email: str, ip_address: str | None) -> bool:
        with self.store.atomic() as connection:
            now = self.clock()
            for scope, value, limit in self._keys(email, ip_address):
                _, state = self._state(connection, scope, value, now)
                if state["locked_until"] > now or len(state["events"]) >= limit:
                    return True
            return False

    def begin_attempt(self, *, email: str, ip_address: str | None) -> str:
        token = uuid.uuid4().hex
        with self.store.atomic() as connection:
            now = self.clock()
            for scope, value, limit in self._keys(email, ip_address):
                key, state = self._state(connection, scope, value, now)
                if state["locked_until"] > now or len(state["events"]) >= limit:
                    raise RateLimitError(
                        LOCKOUT_MESSAGE,
                        details={
                            "retry_after_seconds": max(
                                1,
                                math.ceil(
                                    max(state["locked_until"], now + self.lease_seconds) - now
                                ),
                            )
                        },
                    )
                state["events"].append(
                    {"id": token, "at": now, "lease": now + self.lease_seconds, "state": "inflight"}
                )
                self.store.write(
                    connection, scope, key, state, max(now + self._window, state["locked_until"])
                )
        return token

    def _finish(
        self, *, email: str, ip_address: str | None, attempt_id: str | None, success: bool
    ) -> None:
        token = attempt_id or self.begin_attempt(email=email, ip_address=ip_address)
        with self.store.atomic() as connection:
            now = self.clock()
            for scope, value, limit in self._keys(email, ip_address):
                key, state = self._state(connection, scope, value, now)
                own = next((event for event in state["events"] if event["id"] == token), None)
                if own is None:
                    raise RateLimitError(LOCKOUT_MESSAGE)
                if success:
                    state["events"] = [
                        event
                        for event in state["events"]
                        if event["id"] != token
                        and not (scope == "login_account" and event["state"] == "failed")
                    ]
                    if scope == "login_account":
                        state["locked_until"] = 0.0
                else:
                    own.update(state="failed", at=now)
                    if sum(event["state"] == "failed" for event in state["events"]) >= limit:
                        state["locked_until"] = now + self._lockout_seconds
                self.store.write(
                    connection, scope, key, state, max(now + self._window, state["locked_until"])
                )

    def record_failure(
        self, *, email: str, ip_address: str | None, attempt_id: str | None = None
    ) -> None:
        self._finish(email=email, ip_address=ip_address, attempt_id=attempt_id, success=False)

    def record_success(
        self, *, email: str, ip_address: str | None, attempt_id: str | None = None
    ) -> None:
        self._finish(email=email, ip_address=ip_address, attempt_id=attempt_id, success=True)
