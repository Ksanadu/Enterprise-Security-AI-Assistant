"""Preview/apply an approved retention policy or manage an explicit preservation hold."""

import argparse
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "apply", "hold", "release"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--resource", choices=("conversation", "ticket", "audit"))
    parser.add_argument("--id", type=int)
    parser.add_argument(
        "--case", help="Preservation case identifier, never credentials or incident prose"
    )
    args = parser.parse_args()
    try:
        from app.core.config import get_settings
        from app.db.backup import backup
        from app.db.migrations import require_current_schema
        from app.db.session import get_engine, get_session_factory
        from app.services.retention import backup_directory, run_retention, set_hold

        settings = get_settings()
        require_current_schema(get_engine(settings))
        if args.action in {"hold", "release"}:
            if args.resource is None or args.id is None or not args.case or args.backup_dir is None:
                raise ValueError(
                    "Preservation mutation needs resource, id, case and fresh backup directory."
                )
            import uuid

            folder = backup_directory(str(args.backup_dir))
            if settings.sqlite_path is None:
                raise ValueError("SQLite required.")
            backup(settings.sqlite_path, folder / ("hold-change-" + uuid.uuid4().hex + ".db"))
            with get_session_factory(settings)() as session:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                result = set_hold(
                    session, args.resource, args.id, args.case, release=args.action == "release"
                )
                session.commit()
        else:
            overrides = {}
            if args.policy:
                overrides["retention_policy_file"] = str(args.policy)
            if args.backup_dir:
                overrides["retention_backup_dir"] = str(args.backup_dir)
            result = run_retention(
                settings.model_copy(update=overrides), apply=args.action == "apply"
            )
        print(json.dumps(result))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
