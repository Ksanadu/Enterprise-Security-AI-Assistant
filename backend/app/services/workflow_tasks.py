"""Persisted workflow decisions with isolated attempts and explicit recovery."""

from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.ai.prompt_guard import GuardResult
from app.ai.risk_classifier import RiskAssessment, RiskSignal
from app.ai.turn_analysis import TurnAnalysis
from app.core.enums import AuditOutcome, Intent, RiskLevel, Role, Severity, TicketStatus
from app.core.errors import NotFoundError
from app.db.models import Conversation, Ticket, TicketEvent, User, WorkflowTask
from app.security.audit import AuditAction, record_audit
from app.security.redaction import redact_credentials
from app.services.workflow_manager import WorkflowDecision, WorkflowManager

logger = logging.getLogger(__name__)


class WorkflowTasks:
    def __init__(self, workflow: WorkflowManager) -> None:
        self.workflow = workflow

    def prepare(
        self,
        session: Session,
        *,
        decision: WorkflowDecision,
        analysis: TurnAnalysis,
        user: User,
        conversation_id: int,
        user_message_id: int,
        question: str,
    ) -> WorkflowTask:
        task = session.scalar(
            select(WorkflowTask).where(WorkflowTask.user_message_id == user_message_id)
        )
        snapshot = {
            "decision": {
                **dataclasses.asdict(decision),
                "title": redact_credentials(decision.title),
                "description": redact_credentials(decision.description),
            },
            "intent": analysis.intent.value,
            "risk_level": analysis.risk.level.value,
            "risk_signals": [
                {
                    "label": signal.label,
                    "level": signal.level.value,
                    "evidence": redact_credentials(signal.evidence),
                }
                for signal in analysis.risk.signals
            ],
            "blocked": analysis.blocked,
            "question": redact_credentials(question),
        }
        if task is None:
            task = WorkflowTask(
                id=str(uuid.uuid4()),
                user_message_id=user_message_id,
                conversation_id=conversation_id,
                created_by_user_id=user.id,
                status="pending",
                snapshot=snapshot,
            )
            session.add(task)
        elif RiskLevel(snapshot["risk_level"]).rank > RiskLevel(task.snapshot["risk_level"]).rank:
            task.snapshot, task.status = snapshot, "pending"
            task.revision += 1
        session.commit()
        return task

    def run(self, session: Session, task: WorkflowTask) -> Ticket | None:
        if task.status == "completed":
            return session.scalar(select(Ticket).where(Ticket.reference == task.ticket_reference))
        now = dt.datetime.now(dt.UTC)
        claimed = session.scalar(
            update(WorkflowTask)
            .where(
                WorkflowTask.id == task.id,
                or_(WorkflowTask.status == "pending", WorkflowTask.lease_until < now),
                WorkflowTask.status != "completed",
            )
            .values(
                status="processing",
                lease_until=now + dt.timedelta(seconds=60),
                attempts=WorkflowTask.attempts + 1,
            )
            .execution_options(synchronize_session="fetch")
            .returning(WorkflowTask.id)
        )
        session.commit()
        session.refresh(task)
        if claimed is None:
            return (
                session.scalar(select(Ticket).where(Ticket.reference == task.ticket_reference))
                if task.status == "completed"
                else None
            )
        revision = task.revision
        attempt = task.attempts
        task_id = task.id
        snapshot = task.snapshot
        raw = snapshot["decision"]
        decision = WorkflowDecision(
            **{
                **raw,
                "severity": Severity(raw["severity"]),
                "owner_role": Role(raw["owner_role"]),
                "initial_status": TicketStatus(raw["initial_status"]),
            }
        )
        risk = RiskLevel(snapshot["risk_level"])
        analysis = TurnAnalysis(
            intent=Intent(snapshot["intent"]),
            intent_confidence=1.0,
            intent_source="persisted",
            risk=RiskAssessment(
                risk,
                tuple(
                    RiskSignal(signal["label"], RiskLevel(signal["level"]), signal["evidence"])
                    for signal in snapshot.get("risk_signals", [])
                ),
                "persisted",
                decision.reason,
            ),
            guard=GuardResult("block" if snapshot["blocked"] else "allow"),
            peak_risk=risk,
            blocked=snapshot["blocked"],
        )
        user = session.get(User, task.created_by_user_id) if task.created_by_user_id else None
        try:
            with session.begin_nested():
                # Serialize only the short incident write transaction. Concurrent
                # reports for the same conversation must recheck after this lock.
                if task.conversation_id:
                    session.execute(
                        update(Conversation)
                        .where(Conversation.id == task.conversation_id)
                        .values(updated_at=Conversation.updated_at)
                    )
                existing = (
                    self.workflow.tickets.find_open_for_conversation(
                        session, conversation_id=task.conversation_id
                    )
                    if task.conversation_id
                    else None
                )
                # Recovery must not create a second ticket if an earlier attempt
                # committed one before its final result could be acknowledged.
                if existing is not None and decision.action in {"create", "clarify"}:
                    decision = dataclasses.replace(
                        decision, action="escalate" if decision.escalation_required else "none"
                    )
                elif existing is None and decision.action == "escalate":
                    decision = dataclasses.replace(
                        decision, action="create", description=snapshot["question"]
                    )
                if existing is not None:
                    marker = f"Report task {task.id}: "
                    recorded = session.scalar(
                        select(TicketEvent.id).where(
                            TicketEvent.ticket_id == existing.id,
                            TicketEvent.event_type == "report_fact",
                            TicketEvent.note.startswith(marker),
                        )
                    )
                    if recorded is None:
                        self.workflow.tickets.record_event(
                            session,
                            existing,
                            event_type="report_fact",
                            actor=user,
                            automated=True,
                            note=f"{marker}{snapshot['question']}\nAssessed risk: {risk.value}.",
                        )
                ticket = self.workflow.apply(
                    session,
                    decision=decision,
                    user=user,
                    analysis=analysis,
                    conversation_id=task.conversation_id,
                    question=snapshot["question"],
                    existing_ticket=existing,
                )
                if ticket is None and existing is not None:
                    ticket = existing
                session.execute(
                    update(WorkflowTask)
                    .where(
                        WorkflowTask.id == task.id,
                        WorkflowTask.revision == revision,
                        WorkflowTask.attempts == attempt,
                    )
                    .values(
                        status="completed",
                        lease_until=None,
                        ticket_reference=ticket.reference if ticket else None,
                        error_code=None,
                    )
                )
            session.commit()
            session.refresh(task)
            return ticket
        except Exception:
            logger.exception("workflow_task_failed task_id=%s", task_id)
            # The savepoint rolls back the failed attempt. The incident and its
            # task were committed first, so this remains retryable after restart.
            session.rollback()
            session.refresh(task)
            if task.status == "completed":
                return session.scalar(
                    select(Ticket).where(Ticket.reference == task.ticket_reference)
                )
            if task.revision == revision and task.attempts == attempt:
                task.status, task.error_code, task.lease_until = (
                    "pending",
                    "ticket_write_failed",
                    None,
                )
            record_audit(
                session,
                action=AuditAction.WORKFLOW_FAILED,
                actor=user,
                outcome=AuditOutcome.ERROR,
                resource_type="workflow_task",
                resource_id=task.id,
                detail={"error_code": task.error_code, "attempts": task.attempts},
            )
            session.commit()
            return None

    def retry(self, session: Session, task_id: str) -> WorkflowTask:
        task = session.get(WorkflowTask, task_id)
        if task is None:
            raise NotFoundError("Workflow task not found.")
        self.run(session, task)
        return task

    def drain(self, session: Session, limit: int = 50) -> int:
        """Retry a bounded batch; leases coordinate concurrent worker processes."""
        now = dt.datetime.now(dt.UTC)
        ids = list(
            session.scalars(
                select(WorkflowTask.id)
                .where(
                    WorkflowTask.status != "completed",
                    or_(WorkflowTask.status == "pending", WorkflowTask.lease_until < now),
                )
                .order_by(WorkflowTask.updated_at, WorkflowTask.id)
                .limit(limit)
            )
        )
        completed = 0
        for task_id in ids:
            task = self.retry(session, task_id)
            completed += int(task.status == "completed")
        return completed
