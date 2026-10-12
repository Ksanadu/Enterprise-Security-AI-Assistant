"""Approved bounded erasure with preservation holds and verified recovery snapshots."""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, String, and_, cast, delete, exists, func, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.enums import Role, TicketStatus
from app.core.errors import RateLimitError
from app.db.backup import backup, sha256
from app.db.models import (
    AuditLog,
    ChatRequest,
    Conversation,
    DataHold,
    ManualTicketLink,
    Message,
    NotificationOutbox,
    Ticket,
    TicketEvent,
    User,
    WorkflowTask,
)
from app.db.session import get_engine, get_session_factory
from app.security.shared_limits import DatabaseWindowLimiter, SharedBudgetStore

OWNER = "esaa-retention-backups-v1"
ERASED_PRINCIPAL = "retention-erased@example.com"
RECORDS: dict[str, type[Conversation] | type[Ticket] | type[AuditLog]] = {
    "conversation": Conversation,
    "ticket": Ticket,
    "audit": AuditLog,
}


class RetentionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1]
    state: Literal["approved"]
    policy_id: str = Field(min_length=8, max_length=80)
    approved_by: str = Field(min_length=1, max_length=160)
    conversations_days: int | None = Field(default=None, ge=1, le=36500)
    closed_tickets_days: int | None = Field(default=None, ge=1, le=36500)
    completed_workflows_days: int | None = Field(default=None, ge=1, le=36500)
    audit_days: int | None = Field(default=None, ge=1, le=36500)
    notifications_days: int | None = Field(default=None, ge=1, le=36500)
    backup_days: int | None = Field(default=None, ge=1, le=36500)
    batch_limit: int = Field(default=200, ge=1, le=1000)


def read_policy(path: str) -> RetentionPolicy:
    try:
        source = Path(path)
        if source.stat().st_size > 32768:
            raise ValueError("Policy exceeds size bound.")
        return RetentionPolicy.model_validate_json(source.read_bytes())
    except Exception:
        raise RuntimeError("Retention policy is invalid or unreadable.") from None


def held(kind, identity):
    return exists().where(
        DataHold.resource_type == kind,
        DataHold.resource_id == cast(identity, String),
        DataHold.released_at.is_(None),
    )


def ticket_preserved():
    manual_hold = exists().where(
        ManualTicketLink.ticket_id == Ticket.id,
        ManualTicketLink.message_id == Message.id,
        held("conversation", Message.conversation_id),
    )
    return or_(held("ticket", Ticket.id), held("conversation", Ticket.conversation_id), manual_hold)


def conversation_tickets(condition):
    manual = (
        select(ManualTicketLink.ticket_id)
        .join(Message, ManualTicketLink.message_id == Message.id)
        .where(Message.conversation_id == Conversation.id)
        .correlate(Conversation)
    )
    return exists().where(
        or_(Ticket.conversation_id == Conversation.id, Ticket.id.in_(manual)), condition
    )


def workflow_protected():
    return or_(
        held("conversation", WorkflowTask.conversation_id),
        exists().where(
            Ticket.reference == WorkflowTask.ticket_reference,
            or_(
                ticket_preserved(),
                Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
                exists().where(
                    NotificationOutbox.ticket_reference == Ticket.reference,
                    NotificationOutbox.status.notin_(["delivered", "cancelled"]),
                ),
            ),
        ),
    )


def notification_protected():
    return exists().where(
        Ticket.reference == NotificationOutbox.ticket_reference,
        or_(
            ticket_preserved(),
            Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
            exists().where(
                WorkflowTask.ticket_reference == Ticket.reference,
                WorkflowTask.status != "completed",
            ),
        ),
    )


def plan(session: Session, policy: RetentionPolicy, now: dt.datetime) -> dict[str, list]:
    """Only identifiers leave the planner; payloads never enter diagnostics."""
    result: dict[str, list] = {
        kind: [] for kind in ("conversations", "tickets", "workflows", "notifications", "audit")
    }

    def collect(kind, model, days, conditions):
        if days is None:
            return
        cutoff = now - dt.timedelta(days=days)
        statement = (
            select(model.id)
            .where(model.created_at < cutoff, *conditions(cutoff))
            .order_by(model.id)
            .limit(policy.batch_limit)
        )
        result[kind] = list(
            session.scalars(statement.execution_options(include_retention_records=True))
        )

    collect(
        "notifications",
        NotificationOutbox,
        policy.notifications_days,
        lambda cutoff: [
            NotificationOutbox.status.in_(["delivered", "cancelled"]),
            func.coalesce(NotificationOutbox.delivered_at, NotificationOutbox.created_at) < cutoff,
            ~notification_protected(),
        ],
    )
    collect(
        "workflows",
        WorkflowTask,
        policy.completed_workflows_days,
        lambda cutoff: [
            WorkflowTask.status == "completed",
            WorkflowTask.updated_at < cutoff,
            or_(WorkflowTask.lease_until.is_(None), WorkflowTask.lease_until < now),
            ~workflow_protected(),
        ],
    )
    collect(
        "tickets",
        Ticket,
        policy.closed_tickets_days,
        lambda cutoff: [
            Ticket.purged_at.is_(None),
            Ticket.updated_at < cutoff,
            Ticket.status.in_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
            ~ticket_preserved(),
            ~exists().where(TicketEvent.ticket_id == Ticket.id, TicketEvent.created_at >= cutoff),
            ~exists().where(
                WorkflowTask.ticket_reference == Ticket.reference,
                WorkflowTask.status != "completed",
            ),
            ~exists().where(
                NotificationOutbox.ticket_reference == Ticket.reference,
                NotificationOutbox.status.notin_(["delivered", "cancelled"]),
            ),
        ],
    )
    collect(
        "conversations",
        Conversation,
        policy.conversations_days,
        lambda cutoff: [
            Conversation.purged_at.is_(None),
            Conversation.updated_at < cutoff,
            ~held("conversation", Conversation.id),
            ~exists().where(
                Message.conversation_id == Conversation.id, Message.created_at >= cutoff
            ),
            ~exists().where(
                ChatRequest.conversation_id == Conversation.id,
                or_(
                    ChatRequest.updated_at >= cutoff,
                    ChatRequest.lease_until > now,
                    and_(
                        or_(ChatRequest.response.is_(None), ChatRequest.response == JSON.NULL),
                        ChatRequest.lease_until.is_(None),
                    ),
                ),
            ),
            ~exists().where(
                WorkflowTask.conversation_id == Conversation.id, WorkflowTask.status != "completed"
            ),
            ~conversation_tickets(
                or_(
                    ticket_preserved(),
                    Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
                    exists().where(
                        NotificationOutbox.ticket_reference == Ticket.reference,
                        NotificationOutbox.status.notin_(["delivered", "cancelled"]),
                    ),
                )
            ),
            or_(
                Conversation.peak_risk_level.in_(["none", "low"]),
                conversation_tickets(
                    Ticket.status.in_([TicketStatus.CLOSED, TicketStatus.RESOLVED])
                ),
            ),
        ],
    )
    # Preserve audit rows associated with active/held conversations or incidents.
    ticket_audit = exists().where(
        or_(
            AuditLog.resource_id == cast(Ticket.id, String),
            AuditLog.resource_id == Ticket.reference,
        ),
        or_(ticket_preserved(), Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED])),
    )
    conversation_audit = or_(
        held("conversation", AuditLog.resource_id),
        exists().where(
            cast(Conversation.id, String) == AuditLog.resource_id,
            conversation_tickets(
                or_(
                    ticket_preserved(),
                    Ticket.status.notin_([TicketStatus.CLOSED, TicketStatus.RESOLVED]),
                )
            ),
        ),
    )
    workflow_audit = exists().where(
        WorkflowTask.id == AuditLog.resource_id,
        or_(WorkflowTask.status != "completed", workflow_protected()),
    )
    notification_audit = exists().where(
        NotificationOutbox.id == AuditLog.resource_id,
        or_(NotificationOutbox.status.notin_(["delivered", "cancelled"]), notification_protected()),
    )
    collect(
        "audit",
        AuditLog,
        policy.audit_days,
        lambda _cutoff: [
            AuditLog.purged_at.is_(None),
            ~AuditLog.action.like("retention.%"),
            ~held("audit", AuditLog.id),
            ~func.coalesce(
                or_(
                    and_(AuditLog.resource_type == "ticket", ticket_audit),
                    and_(AuditLog.resource_type == "conversation", conversation_audit),
                    and_(AuditLog.resource_type == "workflow_task", workflow_audit),
                    and_(AuditLog.resource_type == "notification", notification_audit),
                ),
                False,
            ),
        ],
    )
    return result


def audit(session: Session, action: str, detail: dict, now: dt.datetime):
    session.add(AuditLog(created_at=now, action=action, resource_type="retention", detail=detail))


def set_hold(session: Session, kind: str, identity: int, case_label: str, *, release=False) -> dict:
    if kind not in RECORDS or identity < 1 or not case_label.strip() or len(case_label) > 128:
        raise ValueError("Invalid preservation scope.")
    model = RECORDS[kind]
    if session.scalar(select(model.id).where(model.id == identity)) is None:
        raise ValueError("Active resource not found; erased records cannot be restored by a hold.")
    now = dt.datetime.now(dt.UTC)
    hold = session.get(DataHold, (kind, str(identity)))
    if release:
        if hold is None or hold.released_at is not None:
            raise ValueError("No active preservation hold.")
        hold.released_at = now
    elif hold is None:
        session.add(
            DataHold(
                resource_type=kind, resource_id=str(identity), case_label=case_label, created_at=now
            )
        )
    elif hold.released_at is not None:
        hold.case_label, hold.created_at, hold.released_at = case_label, now, None
    else:
        return {"status": "already_held"}
    audit(
        session,
        "retention.hold_released" if release else "retention.hold_set",
        {"resource_type": kind, "resource_id": str(identity), "case_label": case_label},
        now,
    )
    return {"status": "released" if release else "held"}


def backup_directory(path: str) -> Path:
    if not path:
        raise ValueError("An explicit retention backup directory is required.")
    folder = Path(path).absolute()
    if any(parent.is_symlink() or parent.is_junction() for parent in (folder, *folder.parents)):
        raise ValueError("Retention backups cannot use linked directories.")
    marker = folder / "retention-owner.json"
    if folder.exists() and not marker.exists() and any(folder.iterdir()):
        raise ValueError("Existing backup directory is not owned by retention.")
    folder.mkdir(parents=True, exist_ok=True)
    if not marker.exists():
        with marker.open("x", encoding="utf-8") as file:
            json.dump({"format": OWNER}, file)
    if marker.is_symlink() or json.loads(marker.read_text()) != {"format": OWNER}:
        raise ValueError("Backup ownership marker differs.")
    return folder.resolve()


def prune_backups(session: Session, folder: Path, policy: RetentionPolicy, now: dt.datetime) -> int:
    if policy.backup_days is None or session.scalar(
        select(func.count()).select_from(DataHold).where(DataHold.released_at.is_(None))
    ):
        return 0
    removed = 0
    cutoff = now - dt.timedelta(days=policy.backup_days)
    # Limit deletions, not examined names: UUID order must not starve older snapshots.
    for manifest in sorted(folder.glob("retention-*.db.manifest.json")):
        if removed >= 100:
            break
        name = manifest.name.removesuffix(".manifest.json")
        if not re.fullmatch(r"retention-[0-9a-f]{32}\.db", name):
            continue
        database = folder / name
        if manifest.is_symlink() or database.is_symlink():
            raise ValueError("Linked backup file refused.")
        data = json.loads(manifest.read_text())
        if data.get("retention_owner") != OWNER:
            continue
        created = dt.datetime.fromisoformat(data["created_at"])
        if created >= cutoff:
            continue
        if database.resolve().parent != folder or database.is_dir():
            raise ValueError("Backup escaped its owned directory.")
        if database.exists() and sha256(database) != data["database_sha256"]:
            raise ValueError("Backup changed; automated expiry refused.")
        state = (
            (database.stat().st_size, database.stat().st_mtime_ns) if database.exists() else None
        )
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        if session.scalar(
            select(func.count()).select_from(DataHold).where(DataHold.released_at.is_(None))
        ):
            session.commit()
            break
        if state is not None:
            current = database.stat()
            if (current.st_size, current.st_mtime_ns) != state:
                raise ValueError("Backup changed while expiry was being prepared.")
        database.unlink(missing_ok=True)
        manifest.unlink()
        audit(
            session,
            "retention.backup_expired",
            {"policy_id": policy.policy_id, "backup_sha256": data["database_sha256"]},
            now,
        )
        session.commit()
        removed += 1
    return removed


def erased_principal(session: Session) -> int:
    user = session.scalar(select(User).where(User.email == ERASED_PRINCIPAL))
    if user is not None:
        if user.is_active or user.role != Role.EMPLOYEE:
            raise RuntimeError("Reserved retention principal conflicts with an active identity.")
        return user.id
    user = User(
        email=ERASED_PRINCIPAL,
        full_name="Erased record identities",
        role=Role.EMPLOYEE,
        password_hash="disabled:" + uuid.uuid4().hex,
        is_active=False,
    )
    session.add(user)
    session.flush()
    return user.id


def apply_plan(session: Session, selected: dict[str, list], now: dt.datetime) -> dict[str, int]:
    counts = {kind: len(ids) for kind, ids in selected.items()}
    session.execute(
        delete(NotificationOutbox).where(NotificationOutbox.id.in_(selected["notifications"]))
    )
    session.execute(delete(WorkflowTask).where(WorkflowTask.id.in_(selected["workflows"])))
    session.execute(delete(TicketEvent).where(TicketEvent.ticket_id.in_(selected["tickets"])))
    session.execute(
        update(Ticket)
        .where(Ticket.id.in_(selected["tickets"]))
        .values(
            title="[retention expired]",
            description="",
            related_query="",
            category="other",
            created_by_user_id=None,
            escalation_required=False,
            purged_at=now,
        )
    )
    if selected["conversations"]:
        principal = erased_principal(session)
        session.execute(
            delete(ChatRequest).where(ChatRequest.conversation_id.in_(selected["conversations"]))
        )
        session.execute(
            update(Message)
            .where(Message.conversation_id.in_(selected["conversations"]))
            .values(
                content="",
                payload=None,
                source_document_ids=None,
                intent=None,
                risk_level=None,
                escalated=False,
                purged_at=now,
            )
        )
        session.execute(
            update(Conversation)
            .where(Conversation.id.in_(selected["conversations"]))
            .values(
                title="[retention expired]", peak_risk_level="low", user_id=principal, purged_at=now
            )
        )
    session.execute(
        update(AuditLog)
        .where(AuditLog.id.in_(selected["audit"]))
        .values(
            actor_user_id=None,
            actor_email=None,
            actor_role=None,
            ip_address=None,
            request_id=None,
            resource_type=None,
            resource_id=None,
            detail=None,
            action="retention.expired",
            purged_at=now,
        )
    )
    return counts


def run_retention(
    settings: Settings,
    *,
    apply=False,
    scheduled=False,
    now: dt.datetime | None = None,
    stop: threading.Event | None = None,
) -> dict:
    policy = read_policy(settings.retention_policy_file)
    now = now or dt.datetime.now(dt.UTC)
    with get_session_factory(settings)() as session:
        initial = plan(session, policy, now)
    if not apply:
        return {
            "status": "dry_run",
            "policy_id": policy.policy_id,
            "counts": {kind: len(ids) for kind, ids in initial.items()},
        }
    if scheduled:
        store = SharedBudgetStore(get_engine(settings), settings.auth_secret_key)
        limiter = DatabaseWindowLimiter(
            store,
            "retention_maintenance",
            limit=1,
            window_seconds=max(120, settings.maintenance_interval_seconds),
        )
        try:
            limiter.check("global")
        except RateLimitError:
            return {"status": "throttled", "counts": {}}
    folder = backup_directory(settings.retention_backup_dir)
    snapshot_path = None
    if any(initial.values()):
        database = settings.sqlite_path
        if database is None or not database.is_file():
            raise ValueError("An existing SQLite source is required.")
        snapshot_path = folder / ("retention-" + uuid.uuid4().hex + ".db")
        result = backup(database, snapshot_path)
        manifest = Path(result["manifest"])
        data = json.loads(manifest.read_text())
        data["retention_owner"] = OWNER
        data["policy_id"] = policy.policy_id
        with manifest.open("w", encoding="utf-8") as file:
            json.dump(data, file)
            file.flush()
            os.fsync(file.fileno())
    if stop is not None and stop.is_set():
        return {"status": "stopped", "counts": {}}
    snapshot_hash = sha256(snapshot_path) if snapshot_path is not None else None
    with get_session_factory(settings)() as session:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        eligible = plan(session, policy, now)
        # Do not erase new/backdated candidates that arrived after the snapshot.
        selected = {
            kind: [identity for identity in ids if identity in initial[kind]]
            for kind, ids in eligible.items()
        }
        counts = apply_plan(session, selected, now)
        if any(counts.values()):
            if snapshot_hash is None:
                raise RuntimeError("Retention requires a verified pre-erasure snapshot.")
            audit(
                session,
                "retention.completed",
                {
                    "policy_id": policy.policy_id,
                    "backup_sha256": snapshot_hash,
                    "counts": counts,
                },
                now,
            )
        session.commit()
    with get_session_factory(settings)() as session:
        pruned = prune_backups(session, folder, policy, now)
        if pruned:
            audit(
                session,
                "retention.backups_expired",
                {"policy_id": policy.policy_id, "count": pruned},
                now,
            )
            session.commit()
    return {
        "status": "completed",
        "counts": counts,
        "backups_expired": pruned,
        "backup_verified": snapshot_path is not None,
    }


def erase_conversation(session: Session, identity: int, now: dt.datetime) -> None:
    """Use the same identity-preserving erasure for an owner's delete request."""
    session.execute(
        update(WorkflowTask)
        .where(WorkflowTask.conversation_id == identity)
        .values(conversation_id=None, user_message_id=None)
    )
    session.execute(
        update(Ticket).where(Ticket.conversation_id == identity).values(conversation_id=None)
    )
    selected: dict[str, list] = {
        kind: [] for kind in ("conversations", "tickets", "workflows", "notifications", "audit")
    }
    selected["conversations"] = [identity]
    apply_plan(session, selected, now)
