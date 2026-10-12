"""Freeze the current baseline once, using a fresh in-memory SQLite schema.

This is a development utility, not an operator upgrade. Existing revision files
are never overwritten; later changes must be new reviewed revisions.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

from alembic.autogenerate import produce_migrations, render_python_code
from alembic.migration import MigrationContext
from alembic.operations import ops
from sqlalchemy import create_engine, inspect

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.db import models  # noqa: E402,F401
from app.db.base import Base  # noqa: E402
from app.db.migrations import schema_signature  # noqa: E402


def generate() -> None:
    folder = BACKEND / "migrations"
    revision_file = folder / "versions" / "20261012_01_baseline.py"
    schema_file = folder / "baseline-schema.json"
    if revision_file.exists() or schema_file.exists():
        raise FileExistsError("Baseline already frozen; create a new migration revision.")
    engine = create_engine("sqlite://")
    try:
        with engine.connect() as connection:
            generated = produce_migrations(MigrationContext.configure(connection), Base.metadata)
            grouped = defaultdict(list)
            for operation in generated.upgrade_ops.ops:
                grouped[operation.table_name].append(operation)
            lines = [
                '"""Frozen current schema, with validated adoption of existing prototype data."""',
                "from alembic import op",
                "import sqlalchemy as sa",
                "from app.db.migrations import validate_baseline",
                "revision = '20261012_01'",
                "down_revision = None",
                "branch_labels = None",
                "depends_on = None",
                "def upgrade():",
                "    connection = op.get_bind()",
                "    validate_baseline(connection)",
                "    existing = set(sa.inspect(connection).get_table_names())",
            ]
            for name, operations in grouped.items():
                lines.append(f"    if {name!r} not in existing:")
                body = render_python_code(
                    ops.UpgradeOps(operations), migration_context=MigrationContext.configure(connection)
                ).splitlines()
                lines.extend("    " + line for line in body if not line.lstrip().startswith("#"))
            names = list(grouped)
            lines.extend(
                [
                    "def downgrade():",
                    "    connection = op.get_bind()",
                    f"    names = {names!r}",
                    "    for name in names:",
                "        if connection.execute(sa.select(sa.func.count()).select_from(sa.table(name))).scalar():",
                    "            raise RuntimeError('Baseline rollback refused: business data exists; restore a verified backup instead.')",
                    "    for name in reversed(names):",
                    "        op.drop_table(name)",
                ]
            )
            Base.metadata.create_all(connection)
            inspector = inspect(connection)
            schema = {
                name: schema_signature(inspector, name) for name in inspector.get_table_names()
            }
        revision_file.parent.mkdir(parents=True, exist_ok=True)
        revision_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        schema_file.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    finally:
        engine.dispose()


if __name__ == "__main__":
    generate()
