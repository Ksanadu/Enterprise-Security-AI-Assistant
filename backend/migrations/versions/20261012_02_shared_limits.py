"""Persistent budgets shared by every SQLite worker and surviving restart."""

import sqlalchemy as sa
from alembic import op

revision = "20261012_02"
down_revision = "20261012_01"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "security_limit_buckets",
        sa.Column("scope", sa.String(64), primary_key=True),
        sa.Column("key_hash", sa.String(64), primary_key=True),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("locked_until", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False),
    )
    op.create_index(
        "ix_security_limit_buckets_expires_at", "security_limit_buckets", ["expires_at"]
    )


def downgrade():
    connection = op.get_bind()
    count = connection.execute(
        sa.select(sa.func.count()).select_from(sa.table("security_limit_buckets"))
    ).scalar()
    if count:
        raise RuntimeError(
            "Rollback refused: shared security budgets exist; use a verified backup and controlled release rollback."
        )
    op.drop_table("security_limit_buckets")
