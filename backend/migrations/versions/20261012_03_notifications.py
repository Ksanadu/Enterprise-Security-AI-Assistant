"""Durable notification intent, independent of model and HTTP receiver."""

import sqlalchemy as sa
from alembic import op

revision = "20261012_03"
down_revision = "20261012_02"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "notification_outbox",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("event_key", sa.String(160), nullable=False, unique=True),
        sa.Column("ticket_id", sa.Integer(), sa.ForeignKey("tickets.id", ondelete="SET NULL")),
        sa.Column("ticket_reference", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("attempt_limit", sa.Integer(), nullable=False),
        sa.Column("lease_token", sa.String(36)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("next_reminder_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("error_code", sa.String(64)),
    )
    for column in ("ticket_id", "status", "next_attempt_at", "next_reminder_at"):
        op.create_index(f"ix_notification_outbox_{column}", "notification_outbox", [column])


def downgrade():
    if (
        op.get_bind()
        .execute(sa.select(sa.func.count()).select_from(sa.table("notification_outbox")))
        .scalar()
    ):
        raise RuntimeError(
            "Rollback refused: notification records exist; preserve delivery evidence."
        )
    op.drop_table("notification_outbox")
