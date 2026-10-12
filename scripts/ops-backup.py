"""Consistent SQLite backup/restore CLI; shared with scheduled retention."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.db.backup import backup as backup
from app.db.backup import clone_database as clone_database
from app.db.backup import inspect_database as inspect_database
from app.db.backup import restore as restore
from app.db.backup import sha256 as sha256


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "restore"))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (backup if args.action == "backup" else restore)(args.database, args.output)
    except Exception as exc:
        # SQLite errors can contain values/SQL. Report a category without data.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
