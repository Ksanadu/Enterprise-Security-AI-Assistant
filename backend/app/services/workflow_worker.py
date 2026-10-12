"""Bounded background recovery using its own database sessions."""

from __future__ import annotations

import asyncio
import logging

from app.core.config import Settings
from app.db.session import get_session_factory
from app.services.workflow_tasks import WorkflowTasks

logger = logging.getLogger(__name__)


def recover(tasks: WorkflowTasks, settings: Settings) -> int:
    with get_session_factory(settings)() as session:
        return tasks.drain(session)


async def recovery_loop(tasks: WorkflowTasks, settings: Settings) -> None:
    while True:
        await asyncio.sleep(settings.workflow_retry_interval_seconds)
        try:
            await asyncio.to_thread(recover, tasks, settings)
        except Exception:
            logger.exception("workflow_recovery_failed")
