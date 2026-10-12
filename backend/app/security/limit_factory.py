"""Runtime defaults use shared budgets; process-local limits remain a test/demo option."""

from app.core.config import Settings
from app.db.session import get_engine
from app.security.login_guard import LoginGuard
from app.security.rate_limit import SlidingWindowLimiter
from app.security.shared_limits import DatabaseLoginGuard, DatabaseWindowLimiter, SharedBudgetStore


def store(settings: Settings) -> SharedBudgetStore:
    return SharedBudgetStore(get_engine(settings), settings.auth_secret_key)


def window_limiter(settings: Settings, *, scope: str, limit: int) -> SlidingWindowLimiter:
    return (
        DatabaseWindowLimiter(store(settings), scope, limit=limit)
        if settings.shared_security_limits
        else SlidingWindowLimiter(limit=limit)
    )


def login_guard(settings: Settings) -> LoginGuard:
    if settings.shared_security_limits:
        return DatabaseLoginGuard(
            store(settings),
            max_attempts=settings.auth_max_login_attempts,
            ip_max_attempts=settings.auth_max_login_attempts_per_ip,
            window_seconds=settings.auth_login_window_seconds,
            lockout_seconds=settings.auth_lockout_seconds,
            lease_seconds=settings.auth_attempt_lease_seconds,
        )
    return LoginGuard(
        max_attempts=settings.auth_max_login_attempts,
        ip_max_attempts=settings.auth_max_login_attempts_per_ip,
        window_seconds=settings.auth_login_window_seconds,
        lockout_seconds=settings.auth_lockout_seconds,
    )
