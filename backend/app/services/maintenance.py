"""Scheduled bounded cleanup of expired budgets and old expired auth sessions."""

from __future__ import annotations

import asyncio
import logging
import threading
import time

from sqlalchemy import delete, select

from app.core.config import Settings
from app.db.models import SecurityLimitBucket
from app.db.session import get_session_factory
from app.security.audit import record_audit
from app.security.sessions import purge_expired_sessions

logger = logging.getLogger(__name__)


def maintain(
    settings: Settings, *, now_epoch: float | None = None, stop: threading.Event | None = None
) -> dict[str, int]:
    with get_session_factory(settings)() as session:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        now = time.time() if now_epoch is None else now_epoch
        # Bound each pass. Expiry includes live lockouts and in-flight leases.
        expired = session.execute(
            select(SecurityLimitBucket.scope, SecurityLimitBucket.key_hash)
            .where(SecurityLimitBucket.expires_at <= now)
            .order_by(SecurityLimitBucket.expires_at)
            .limit(1000)
        ).all()
        for scope, key in expired:
            session.execute(
                delete(SecurityLimitBucket).where(
                    SecurityLimitBucket.scope == scope, SecurityLimitBucket.key_hash == key
                )
            )
        sessions = purge_expired_sessions(
            session, retention_days=settings.auth_session_retention_days
        )
        counts = {"expired_budget_rows": len(expired), "expired_session_rows": sessions}
        if any(counts.values()):
            record_audit(session, action="maintenance.completed", detail=counts)
        session.commit()
    if settings.retention_policy_file:
        from app.services.retention import run_retention

        retained = run_retention(settings, apply=True, scheduled=True, stop=stop)
        counts.update({"erased_" + kind: value for kind, value in retained["counts"].items()})
    return counts


async def maintenance_loop(settings: Settings) -> None:
    while True:
        await asyncio.sleep(settings.maintenance_interval_seconds)
        stop = threading.Event()
        job = asyncio.create_task(asyncio.to_thread(maintain, settings, stop=stop))
        try:
            counts = await asyncio.shield(job)
            logger.info(
                "maintenance_completed budget_rows=%s session_rows=%s",
                counts["expired_budget_rows"],
                counts["expired_session_rows"],
            )
        except asyncio.CancelledError:
            stop.set()
            await job
            raise
        except Exception as exc:
            logger.error("maintenance_failed error_type=%s", type(exc).__name__)
