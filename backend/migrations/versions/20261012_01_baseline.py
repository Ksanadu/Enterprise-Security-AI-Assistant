"""Frozen current schema, with validated adoption of existing prototype data."""

import sqlalchemy as sa
from alembic import op

from app.db.migrations import validate_baseline

revision = "20261012_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    validate_baseline(connection)
    existing = set(sa.inspect(connection).get_table_names())
    if "ticket_sequences" not in existing:
        op.create_table(
            "ticket_sequences",
            sa.Column("key", sa.String(length=32), nullable=False),
            sa.Column("value", sa.Integer(), nullable=False),
            sa.PrimaryKeyConstraint("key"),
        )
    if "users" not in existing:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("full_name", sa.String(length=160), nullable=False),
            sa.Column(
                "role",
                sa.Enum("employee", "it", "security", name="role", native_enum=False, length=32),
                nullable=False,
            ),
            sa.Column("password_hash", sa.String(length=255), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
        op.create_index(op.f("ix_users_role"), "users", ["role"], unique=False)
    if "audit_logs" not in existing:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_email", sa.String(length=255), nullable=True),
            sa.Column("actor_role", sa.String(length=32), nullable=True),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("resource_type", sa.String(length=64), nullable=True),
            sa.Column("resource_id", sa.String(length=64), nullable=True),
            sa.Column(
                "outcome",
                sa.Enum(
                    "success", "denied", "error", name="auditoutcome", native_enum=False, length=16
                ),
                nullable=False,
            ),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("detail", sa.JSON(), nullable=True),
            sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
        op.create_index(
            op.f("ix_audit_logs_actor_role"), "audit_logs", ["actor_role"], unique=False
        )
        op.create_index(
            op.f("ix_audit_logs_actor_user_id"), "audit_logs", ["actor_user_id"], unique=False
        )
        op.create_index(
            "ix_audit_logs_created_action", "audit_logs", ["created_at", "action"], unique=False
        )
        op.create_index(
            op.f("ix_audit_logs_created_at"), "audit_logs", ["created_at"], unique=False
        )
        op.create_index(
            op.f("ix_audit_logs_request_id"), "audit_logs", ["request_id"], unique=False
        )
    if "conversations" not in existing:
        op.create_table(
            "conversations",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("peak_risk_level", sa.String(length=16), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_conversations_created_at"), "conversations", ["created_at"], unique=False
        )
        op.create_index(
            op.f("ix_conversations_user_id"), "conversations", ["user_id"], unique=False
        )
    if "user_sessions" not in existing:
        op.create_table(
            "user_sessions",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("jti", sa.String(length=64), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_reason", sa.String(length=64), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("user_agent", sa.String(length=255), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("jti", name="uq_user_sessions_jti"),
        )
        op.create_index(
            op.f("ix_user_sessions_expires_at"), "user_sessions", ["expires_at"], unique=False
        )
        op.create_index(op.f("ix_user_sessions_jti"), "user_sessions", ["jti"], unique=False)
        op.create_index(
            op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False
        )
        op.create_index(
            "ix_user_sessions_user_revoked",
            "user_sessions",
            ["user_id", "revoked_at"],
            unique=False,
        )
    if "messages" not in existing:
        op.create_table(
            "messages",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("conversation_id", sa.Integer(), nullable=False),
            sa.Column(
                "role",
                sa.Enum(
                    "user", "assistant", "system", name="messagerole", native_enum=False, length=16
                ),
                nullable=False,
            ),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("payload", sa.JSON(), nullable=True),
            sa.Column("source_document_ids", sa.JSON(), nullable=True),
            sa.Column("intent", sa.String(length=32), nullable=True),
            sa.Column("risk_level", sa.String(length=16), nullable=True),
            sa.Column("escalated", sa.Boolean(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_messages_conversation_id"), "messages", ["conversation_id"], unique=False
        )
        op.create_index(op.f("ix_messages_created_at"), "messages", ["created_at"], unique=False)
        op.create_index(op.f("ix_messages_intent"), "messages", ["intent"], unique=False)
        op.create_index(
            "ix_messages_intent_risk", "messages", ["intent", "risk_level"], unique=False
        )
        op.create_index(op.f("ix_messages_risk_level"), "messages", ["risk_level"], unique=False)
    if "tickets" not in existing:
        op.create_table(
            "tickets",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("reference", sa.String(length=32), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("category", sa.String(length=64), nullable=False),
            sa.Column(
                "severity",
                sa.Enum(
                    "low",
                    "medium",
                    "high",
                    "critical",
                    name="severity",
                    native_enum=False,
                    length=16,
                ),
                nullable=False,
            ),
            sa.Column(
                "status",
                sa.Enum(
                    "open",
                    "in_progress",
                    "escalated",
                    "resolved",
                    "closed",
                    name="ticketstatus",
                    native_enum=False,
                    length=16,
                ),
                nullable=False,
            ),
            sa.Column(
                "source",
                sa.Enum(
                    "ai_auto",
                    "ai_suggested",
                    "user_request",
                    "security_team",
                    name="ticketsource",
                    native_enum=False,
                    length=16,
                ),
                nullable=False,
            ),
            sa.Column("escalation_required", sa.Boolean(), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column(
                "owner_role",
                sa.Enum("employee", "it", "security", name="role", native_enum=False, length=32),
                nullable=False,
            ),
            sa.Column("conversation_id", sa.Integer(), nullable=True),
            sa.Column("related_query", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("reference", name="uq_tickets_reference"),
        )
        op.create_index(
            op.f("ix_tickets_conversation_id"), "tickets", ["conversation_id"], unique=False
        )
        op.create_index(op.f("ix_tickets_created_at"), "tickets", ["created_at"], unique=False)
        op.create_index(
            op.f("ix_tickets_created_by_user_id"), "tickets", ["created_by_user_id"], unique=False
        )
        op.create_index(op.f("ix_tickets_owner_role"), "tickets", ["owner_role"], unique=False)
        op.create_index(op.f("ix_tickets_reference"), "tickets", ["reference"], unique=False)
        op.create_index(op.f("ix_tickets_severity"), "tickets", ["severity"], unique=False)
        op.create_index(op.f("ix_tickets_status"), "tickets", ["status"], unique=False)
        op.create_index(
            "ix_tickets_status_severity", "tickets", ["status", "severity"], unique=False
        )
    if "chat_requests" not in existing:
        op.create_table(
            "chat_requests",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=False),
            sa.Column("conversation_id", sa.Integer(), nullable=False),
            sa.Column("request_key", sa.String(length=128), nullable=False),
            sa.Column("question_hash", sa.String(length=64), nullable=False),
            sa.Column("actor_role", sa.String(length=32), nullable=False),
            sa.Column("pending_content", sa.Text(), nullable=False),
            sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("user_message_id", sa.Integer(), nullable=True),
            sa.Column("response", sa.JSON(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_message_id"], ["messages.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "user_id", "conversation_id", "request_key", name="uq_chat_request_key"
            ),
        )
        op.create_index(
            op.f("ix_chat_requests_created_at"), "chat_requests", ["created_at"], unique=False
        )
    if "manual_ticket_links" not in existing:
        op.create_table(
            "manual_ticket_links",
            sa.Column("message_id", sa.Integer(), nullable=False),
            sa.Column("ticket_id", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(["message_id"], ["messages.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["ticket_id"], ["tickets.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("message_id"),
        )
    if "ticket_events" not in existing:
        op.create_table(
            "ticket_events",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("ticket_id", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("event_type", sa.String(length=32), nullable=False),
            sa.Column("from_status", sa.String(length=16), nullable=True),
            sa.Column("to_status", sa.String(length=16), nullable=True),
            sa.Column("from_severity", sa.String(length=16), nullable=True),
            sa.Column("to_severity", sa.String(length=16), nullable=True),
            sa.Column("actor_user_id", sa.Integer(), nullable=True),
            sa.Column("actor_role", sa.String(length=32), nullable=True),
            sa.Column("automated", sa.Boolean(), nullable=False),
            sa.Column("note", sa.Text(), nullable=False),
            sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["ticket_id"], ["tickets.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            op.f("ix_ticket_events_actor_user_id"), "ticket_events", ["actor_user_id"], unique=False
        )
        op.create_index(
            op.f("ix_ticket_events_event_type"), "ticket_events", ["event_type"], unique=False
        )
        op.create_index(
            "ix_ticket_events_ticket_created",
            "ticket_events",
            ["ticket_id", "created_at"],
            unique=False,
        )
        op.create_index(
            op.f("ix_ticket_events_ticket_id"), "ticket_events", ["ticket_id"], unique=False
        )
    if "workflow_tasks" not in existing:
        op.create_table(
            "workflow_tasks",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_message_id", sa.Integer(), nullable=True),
            sa.Column("conversation_id", sa.Integer(), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("revision", sa.Integer(), nullable=False),
            sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("snapshot", sa.JSON(), nullable=False),
            sa.Column("ticket_reference", sa.String(length=32), nullable=True),
            sa.Column("error_code", sa.String(length=64), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["conversation_id"], ["conversations.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["user_message_id"], ["messages.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("user_message_id"),
        )
        op.create_index(
            op.f("ix_workflow_tasks_conversation_id"),
            "workflow_tasks",
            ["conversation_id"],
            unique=False,
        )
        op.create_index(
            op.f("ix_workflow_tasks_created_at"), "workflow_tasks", ["created_at"], unique=False
        )
        op.create_index(
            op.f("ix_workflow_tasks_status"), "workflow_tasks", ["status"], unique=False
        )


def downgrade():
    connection = op.get_bind()
    names = [
        "ticket_sequences",
        "users",
        "audit_logs",
        "conversations",
        "user_sessions",
        "messages",
        "tickets",
        "chat_requests",
        "manual_ticket_links",
        "ticket_events",
        "workflow_tasks",
    ]
    for name in names:
        if connection.execute(sa.select(sa.func.count()).select_from(sa.table(name))).scalar():
            raise RuntimeError(
                "Baseline rollback refused: business data exists; restore a verified backup instead."
            )
    for name in reversed(names):
        op.drop_table(name)
