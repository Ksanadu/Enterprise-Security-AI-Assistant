"""ORM models.

Tables: users, conversations, messages, tickets, audit_logs.
Knowledge-base documents live in Markdown on disk (see ``app/rag``) so the
``allowed_roles`` metadata stays reviewable in version control.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AuditOutcome,
    MessageRole,
    Role,
    Severity,
    TicketSource,
    TicketStatus,
)
from app.db.base import Base, TimestampMixin


def _enum_column(enum_cls: type, **kwargs: Any) -> SAEnum:
    """Store enum *values* (not member names) as VARCHAR for readable SQL."""
    return SAEnum(
        enum_cls,
        native_enum=False,
        validate_strings=True,
        values_callable=lambda cls: [member.value for member in cls],
        **kwargs,
    )


class User(Base, TimestampMixin):
    """An authenticated principal with exactly one role."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    role: Mapped[Role] = mapped_column(
        _enum_column(Role, length=32), nullable=False, default=Role.EMPLOYEE, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    conversations: Mapped[list[Conversation]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User id={self.id} email={self.email!r} role={self.role.value}>"


class Conversation(Base, TimestampMixin):
    """A chat thread owned by exactly one user."""

    __tablename__ = "conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False, default="New conversation")
    #: Highest risk level observed in this conversation, used to keep escalations sticky.
    peak_risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    purged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="conversations")
    messages: Mapped[list[Message]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="Message.id",
    )


class Message(Base, TimestampMixin):
    """One turn in a conversation, including the structured assistant payload."""

    __tablename__ = "messages"
    __table_args__ = (Index("ix_messages_intent_risk", "intent", "risk_level"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(
        ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[MessageRole] = mapped_column(_enum_column(MessageRole, length=16), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: Full structured assistant response (intent, risk, sources, actions, ...).
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    #: Ids of knowledge documents that were *authorized and used* for this answer.
    source_document_ids: Mapped[list[str] | None] = mapped_column(JSON)

    # Classification is denormalised out of `payload` so the dashboard can
    # aggregate with SQL instead of loading every message into Python. The
    # payload remains the full record; these columns are the queryable summary.
    intent: Mapped[str | None] = mapped_column(String(32), index=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), index=True)
    escalated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    purged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    conversation: Mapped[Conversation] = relationship(back_populates="messages")


class Ticket(Base, TimestampMixin):
    """A security or IT ticket, optionally created by the AI workflow."""

    __tablename__ = "tickets"
    __table_args__ = (
        UniqueConstraint("reference", name="uq_tickets_reference"),
        Index("ix_tickets_status_severity", "status", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(String(64), nullable=False, default="security")
    severity: Mapped[Severity] = mapped_column(
        _enum_column(Severity, length=16), nullable=False, default=Severity.LOW, index=True
    )
    status: Mapped[TicketStatus] = mapped_column(
        _enum_column(TicketStatus, length=16),
        nullable=False,
        default=TicketStatus.OPEN,
        index=True,
    )
    source: Mapped[TicketSource] = mapped_column(
        _enum_column(TicketSource, length=16), nullable=False, default=TicketSource.AI_AUTO
    )
    escalation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    #: Role expected to own the ticket (least-privileged role that may handle it).
    owner_role: Mapped[Role] = mapped_column(
        _enum_column(Role, length=32), nullable=False, default=Role.SECURITY, index=True
    )
    conversation_id: Mapped[int | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"), index=True
    )
    #: Truncated copy of the triggering user query (audit + triage context).
    related_query: Mapped[str] = mapped_column(Text, nullable=False, default="")
    purged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    created_by: Mapped[User | None] = relationship()
    events: Mapped[list[TicketEvent]] = relationship(
        back_populates="ticket",
        cascade="all, delete-orphan",
        order_by="TicketEvent.id",
    )

    @property
    def is_open(self) -> bool:
        return not self.status.is_terminal

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"<Ticket {self.reference} severity={self.severity.value} status={self.status.value}>"
        )


class TicketEvent(Base):
    """One entry in a ticket's history.

    Append-only, like the audit log: the timeline is what a reviewer reads after
    the fact to understand how a ticket progressed, so entries are never edited
    or removed.
    """

    __tablename__ = "ticket_events"
    __table_args__ = (Index("ix_ticket_events_ticket_created", "ticket_id", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ticket_id: Mapped[int] = mapped_column(
        ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    #: created | status_changed | escalated | severity_changed | note
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str | None] = mapped_column(String(16))
    from_severity: Mapped[str | None] = mapped_column(String(16))
    to_severity: Mapped[str | None] = mapped_column(String(16))
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_role: Mapped[str | None] = mapped_column(String(32))
    #: True when the system rather than a person produced the event.
    automated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    note: Mapped[str] = mapped_column(Text, nullable=False, default="")

    ticket: Mapped[Ticket] = relationship(back_populates="events")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<TicketEvent ticket_id={self.ticket_id} type={self.event_type}>"


class AuditLog(Base):
    """Append-only audit trail.

    Nothing in the application updates or deletes rows in this table; the audit
    service only ever inserts.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_created_action", "created_at", "action"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_email: Mapped[str | None] = mapped_column(String(255))
    actor_role: Mapped[str | None] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[AuditOutcome] = mapped_column(
        _enum_column(AuditOutcome, length=16), nullable=False, default=AuditOutcome.SUCCESS
    )
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    purged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog id={self.id} action={self.action} outcome={self.outcome.value}>"


class UserSession(Base):
    """A server-side record of one issued access token.

    A signed JWT cannot be withdrawn once it is issued: it stays valid until it
    expires. Recording each token here makes revocation possible - "sign out",
    "sign out everywhere", and immediate invalidation after a password reset or a
    suspected compromise all work by marking the record revoked.

    The record is keyed by the token's ``jti`` claim, which is unique per token.
    """

    __tablename__ = "user_sessions"
    __table_args__ = (
        UniqueConstraint("jti", name="uq_user_sessions_jti"),
        Index("ix_user_sessions_user_revoked", "user_id", "revoked_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))

    user: Mapped[User] = relationship()

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        state = "revoked" if self.is_revoked else "active"
        return f"<UserSession id={self.id} user_id={self.user_id} {state}>"


class WorkflowTask(Base, TimestampMixin):
    """Durable incident work; survives model failure, retries and chat deletion."""

    __tablename__ = "workflow_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_message_id: Mapped[int | None] = mapped_column(
        ForeignKey("messages.id", ondelete="SET NULL"), unique=True
    )
    conversation_id: Mapped[int | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"), index=True
    )
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    ticket_reference: Mapped[str | None] = mapped_column(String(32))
    error_code: Mapped[str | None] = mapped_column(String(64))


class TicketSequence(Base):
    __tablename__ = "ticket_sequences"
    key: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[int] = mapped_column(Integer, nullable=False)


class ChatRequest(Base, TimestampMixin):
    """A client request key names one turn, including an in-progress turn."""

    __tablename__ = "chat_requests"
    __table_args__ = (
        UniqueConstraint("user_id", "conversation_id", "request_key", name="uq_chat_request_key"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    conversation_id: Mapped[int] = mapped_column(ForeignKey("conversations.id", ondelete="CASCADE"))
    request_key: Mapped[str] = mapped_column(String(128))
    question_hash: Mapped[str] = mapped_column(String(64))
    actor_role: Mapped[str] = mapped_column(String(32))
    pending_content: Mapped[str] = mapped_column(Text, default="")
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    user_message_id: Mapped[int | None] = mapped_column(
        ForeignKey("messages.id", ondelete="SET NULL")
    )
    response: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class ManualTicketLink(Base):
    """A message can be used to request at most one manual follow-up ticket."""

    __tablename__ = "manual_ticket_links"
    message_id: Mapped[int] = mapped_column(
        ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True
    )
    ticket_id: Mapped[int] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"))


class SecurityLimitBucket(Base):
    """Shared request/failure budgets; HMAC keys omit raw account and IP values."""

    __tablename__ = "security_limit_buckets"
    scope: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    events: Mapped[list[Any]] = mapped_column(JSON, nullable=False)
    locked_until: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)


class NotificationOutbox(Base):
    """Transactional intent; delivered means accepted by the receiver."""

    __tablename__ = "notification_outbox"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    ticket_id: Mapped[int | None] = mapped_column(
        ForeignKey("tickets.id", ondelete="SET NULL"), index=True
    )
    ticket_reference: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempt_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    lease_token: Mapped[str | None] = mapped_column(String(36))
    lease_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    next_reminder_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    error_code: Mapped[str | None] = mapped_column(String(64))


class DataHold(Base):
    """Operator-managed preservation; history lives in the audit."""

    __tablename__ = "data_holds"
    resource_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    resource_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_label: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
