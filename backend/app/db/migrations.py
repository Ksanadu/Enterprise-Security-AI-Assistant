"""Versioned SQLite migration helpers; never rebuild tables on application startup."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, inspect

BACKEND = Path(__file__).resolve().parents[2]


def configuration() -> Config:
    return Config(str(BACKEND / "alembic.ini"))


def schema_signature(inspector: Any, name: str) -> dict[str, Any]:
    def ordered(rows, keys):
        values = [{key: row.get(key) for key in keys} for row in rows]
        return sorted(values, key=lambda row: json.dumps(row, sort_keys=True))

    return {
        "columns": {
            column["name"]: {
                "type": str(column["type"]),
                "nullable": column["nullable"],
                "primary_key": column["primary_key"],
                "default": column.get("default"),
            }
            for column in inspector.get_columns(name)
        },
        "indexes": ordered(inspector.get_indexes(name), ("column_names", "unique")),
        "unique": ordered(inspector.get_unique_constraints(name), ("column_names",)),
        "foreign_keys": ordered(
            inspector.get_foreign_keys(name),
            ("constrained_columns", "referred_table", "referred_columns", "options"),
        ),
    }


def validate_baseline(connection: Connection) -> None:
    """Adopt only the frozen schema; reject unknown drift without deleting data."""
    expected = json.loads((BACKEND / "migrations" / "baseline-schema.json").read_text())
    inspector = inspect(connection)
    names = set(inspector.get_table_names()) - {"alembic_version"}
    if names - set(expected):
        raise RuntimeError(
            "Unversioned database has unknown tables; operator schema review required."
        )
    for name in names:
        if schema_signature(inspector, name) != expected[name]:
            raise RuntimeError(
                f"Unversioned database schema drift in {name}; migration refused without data loss."
            )


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def head_revision() -> str:
    head = ScriptDirectory.from_config(configuration()).get_current_head()
    if head is None:
        raise RuntimeError("Database migration head is missing.")
    return head


def require_current_schema(engine: Engine) -> None:
    if current_revision(engine) != head_revision():
        raise RuntimeError(
            "Database migration required. Back up data and run 'python -m alembic upgrade head' before startup."
        )


def upgrade_database(engine: Engine, revision: str = "head") -> None:
    if engine.dialect.name != "sqlite":
        raise RuntimeError(
            "Only SQLite migrations have been accepted; another database requires driver and transaction acceptance."
        )
    config = configuration()
    with engine.connect() as connection, connection.begin():
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, revision)
