"""Operator migration entry point; URLs come from Settings, not command output."""

from alembic import context
from sqlalchemy import create_engine, pool

from app.db import models  # noqa: F401 -- register metadata for autogeneration
from app.db.base import Base

configuration = context.config


def migrate(connection):
    context.configure(connection=connection, target_metadata=Base.metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    raise RuntimeError(
        "This SQLite migration must inspect the actual schema; offline SQL is unsupported."
    )
elif configuration.attributes.get("connection") is not None:
    migrate(configuration.attributes["connection"])
else:
    from app.core.config import get_settings

    try:
        engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    except Exception:
        raise RuntimeError("Migration configuration unavailable; verify environment privately.") from None
    try:
        with engine.connect() as connection, connection.begin():
            if connection.dialect.name == "sqlite":
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            migrate(connection)
    finally:
        engine.dispose()
