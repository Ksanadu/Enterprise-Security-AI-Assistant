"""Preservation holds and non-reusable erased record identities."""

import sqlalchemy as sa
from alembic import op

revision = "20261013_04"
down_revision = "20261012_03"
branch_labels = None
depends_on = None


def upgrade():
    for table in ("conversations", "messages", "tickets", "audit_logs"):
        op.add_column(table, sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "data_holds",
        sa.Column("resource_type", sa.String(32), primary_key=True),
        sa.Column("resource_id", sa.String(64), primary_key=True),
        sa.Column("case_label", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True)),
    )


def downgrade():
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT COUNT(*) FROM data_holds")).scalar():
        raise RuntimeError("Rollback refused: preservation history exists.")
    for table in ("conversations", "messages", "tickets", "audit_logs"):
        records = sa.table(table, sa.column("purged_at"))
        if connection.execute(
            sa.select(sa.func.count()).select_from(records).where(records.c.purged_at.is_not(None))
        ).scalar():
            raise RuntimeError("Rollback refused: erased identities must remain hidden.")
    op.drop_table("data_holds")
    for table in ("conversations", "messages", "tickets", "audit_logs"):
        op.drop_column(table, "purged_at")
