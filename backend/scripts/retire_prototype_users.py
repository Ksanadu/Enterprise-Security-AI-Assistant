"""Dry-run by default; explicitly retire prototype users after verified backup."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def retire(*, apply: bool, backup_path: Path | None) -> dict:
    from sqlalchemy import select, update

    from app.core.config import get_settings
    from app.db.backup import backup
    from app.db.migrations import require_current_schema
    from app.db.models import User, UserSession
    from app.db.session import get_engine, get_session_factory
    from app.security.audit import record_audit
    from app.security.production_checks import DEMO_EMAILS

    settings = get_settings()
    database = settings.sqlite_path
    if database is None or not database.is_file():
        raise RuntimeError("An existing SQLite database is required.")
    require_current_schema(get_engine(settings))
    with get_session_factory(settings)() as session:
        ids = list(
            session.scalars(
                select(User.id).where(User.is_active.is_(True), User.email.in_(DEMO_EMAILS))
            )
        )
    if not apply:
        return {"status": "dry_run", "active_prototype_accounts": len(ids), "data_changed": False}
    if backup_path is None:
        raise RuntimeError("An explicit fresh backup destination is required for --apply.")
    backup(database, backup_path)
    with get_session_factory(settings)() as session:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        # Re-read inside the short write transaction. No history or ticket rows
        # are removed; retained principals remain as inactive audit references.
        ids = list(
            session.scalars(
                select(User.id).where(User.is_active.is_(True), User.email.in_(DEMO_EMAILS))
            )
        )
        session.execute(update(User).where(User.id.in_(ids)).values(is_active=False))
        session.execute(
            update(UserSession)
            .where(UserSession.user_id.in_(ids), UserSession.revoked_at.is_(None))
            .values(revoked_at=dt.datetime.now(dt.UTC), revoked_reason="prototype_retired")
        )
        record_audit(
            session, action="production.prototype_accounts_retired", detail={"accounts": len(ids)}
        )
        session.commit()
    return {
        "status": "retired",
        "accounts": len(ids),
        "history_preserved": True,
        "backup_verified": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path)
    args = parser.parse_args()
    try:
        result = retire(apply=args.apply, backup_path=args.backup)
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__}
    print(json.dumps(result))
    raise SystemExit(1 if result["status"] == "failed" else 0)
