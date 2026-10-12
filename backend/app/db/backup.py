"""Consistent SQLite backup and restore to a new database, without overwriting data.

The source is opened read-only. SQLite's backup API includes committed WAL data.
Backup files contain business data: deploy into an operator-only directory.
On Windows, directory ACLs govern access; a POSIX mode is not an ACL substitute.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def inspect_database(path: Path) -> dict:
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("SQLite integrity check failed.")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("SQLite foreign-key check failed.")
        tables = connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        counts = {}
        for name, _ in tables:
            quoted = '"' + name.replace('"', '""') + '"'
            counts[name] = connection.execute(
                f"SELECT COUNT(*) FROM {quoted}"  # noqa: S608 -- escaped identifier from SQLite catalog
            ).fetchone()[0]
        return {
            "table_counts": counts,
            "schema_sha256": hashlib.sha256(
                json.dumps(tables, ensure_ascii=False).encode("utf-8")
            ).hexdigest(),
        }


def clone_database(source: Path, target: Path, *, timeout: float = 60) -> dict:
    source = source.resolve(strict=True)
    if target.is_symlink():
        raise FileExistsError("Destination is a symbolic link; choose a fresh file.")
    target = target.resolve()
    if not source.is_file() or source == target:
        raise ValueError("A distinct SQLite source file is required.")
    if target.exists() or target.is_symlink():
        raise FileExistsError("Destination exists; restore/backup never overwrites a file.")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".esaa-backup-", dir=target.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    deadline = time.monotonic() + timeout

    def progress(_status: int, _remaining: int, _total: int) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("Consistent backup exceeded its time limit.")

    try:
        with (
            closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as origin,
            closing(sqlite3.connect(temporary)) as destination,
        ):
            origin.backup(destination, pages=128, progress=progress, sleep=0.05)
        details = inspect_database(temporary)
        with temporary.open("r+b") as stream:
            os.fsync(stream.fileno())
        # Same-directory hard link publishes atomically and fails if another
        # process has created the target. os.replace would overwrite its data.
        os.link(temporary, target)
        return details
    finally:
        temporary.unlink(missing_ok=True)


def backup(database: Path, output: Path) -> dict:
    if output.is_symlink():
        raise FileExistsError("Backup destination is a symbolic link.")
    output = output.resolve()
    manifest = output.with_name(output.name + ".manifest.json")
    if manifest.exists() or manifest.is_symlink():
        raise FileExistsError("Backup manifest exists; choose a fresh destination.")
    details = clone_database(database, output)
    report = {
        "format": "esaa-sqlite-backup-v1",
        "created_at": dt.datetime.now(dt.UTC).isoformat(),
        "database_sha256": sha256(output),
        **details,
    }
    descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "status": "backup_verified",
        "backup": str(output),
        "manifest": str(manifest),
        **report,
    }


def restore(snapshot: Path, output: Path) -> dict:
    snapshot = snapshot.resolve(strict=True)
    manifest = snapshot.with_name(snapshot.name + ".manifest.json")
    report = json.loads(manifest.read_text(encoding="utf-8"))
    if report.get("format") != "esaa-sqlite-backup-v1":
        raise ValueError("Unsupported backup manifest.")
    if sha256(snapshot) != report["database_sha256"]:
        raise ValueError("Backup checksum differs from the manifest; restore refused.")
    details = inspect_database(snapshot)
    if any(details[key] != report[key] for key in ("table_counts", "schema_sha256")):
        raise ValueError("Backup schema or table counts differ from its manifest.")
    restored = clone_database(snapshot, output)
    if restored != details:
        raise ValueError("Restore verification failed; do not activate this database.")
    return {"status": "restore_verified", "database": str(output.resolve()), **restored}
