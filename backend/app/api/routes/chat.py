"""Chat endpoints.

The assistant surface. Every route resolves the caller from the bearer token,
checks conversation ownership in the service layer, and passes the caller's
*role* - never a client-supplied scope - into retrieval.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.ai.model_budget import model_budget
from app.api.deps import AppSettings, CurrentUser, DbSession, client_ip, per_user_limiter
from app.core.enums import AuditOutcome, Role
from app.core.errors import AppError, ValidationError
from app.core.time import iso_utc
from app.db.models import ChatRequest, Conversation, ManualTicketLink, Message, Ticket, WorkflowTask
from app.schemas.chat import (
    ConversationDetail,
    ConversationListResponse,
    ConversationSummary,
    CreateConversationRequest,
    MessageOut,
    MessagePayload,
    PostMessageRequest,
    PostMessageResponse,
)
from app.security.audit import AuditAction, record_audit
from app.security.rate_limit import SlidingWindowLimiter
from app.security.redaction import redact_credentials
from app.services.chat_service import ChatService
from app.services.knowledge_service import KnowledgeService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])


def get_knowledge(request: Request) -> KnowledgeService:
    from app.api.routes.knowledge import get_knowledge_service

    return get_knowledge_service(request)


def get_chat_service(request: Request) -> ChatService:
    service = getattr(request.app.state, "chat", None)
    if service is None:  # pragma: no cover - only if lifespan did not run
        service = ChatService(get_knowledge(request), request.app.state.settings)
        request.app.state.chat = service
    return service


def message_limiter(request: Request, settings: AppSettings) -> SlidingWindowLimiter:
    """Chat budget adapter, shared across workers by the runtime factory."""
    return per_user_limiter(request, name="chat_limiter", limit=settings.chat_rate_limit_per_minute)


def _iso(value: Any) -> str | None:
    return iso_utc(value)


def to_message_out(
    message: Message,
    allowed_document_ids: frozenset[str] | None = None,
    requested_ticket_reference: str | None = None,
    task: WorkflowTask | None = None,
    ticket: Ticket | None = None,
) -> MessageOut:
    payload = MessagePayload(**message.payload) if message.payload else None
    content = message.content
    if payload and task:
        payload = payload.model_copy(
            update={
                "workflow_status": "submitted"
                if task.status == "completed" and task.ticket_reference
                else "pending",
                "ticket_reference": task.ticket_reference,
                "ticket_created": task.ticket_reference is not None,
                "ticket_status": ticket.status.value if ticket else payload.ticket_status,
            }
        )
    if payload and requested_ticket_reference:
        payload = payload.model_copy(
            update={"requested_ticket_reference": requested_ticket_reference}
        )
    if (
        payload
        and allowed_document_ids is not None
        and any(
            source.document_id not in allowed_document_ids for source in payload.source_documents
        )
    ):
        content = "This earlier answer is unavailable under your current document permissions. Ask again to receive an authorized answer."
        payload = payload.model_copy(
            update={
                "answer": content,
                "source_documents": [],
                "recommended_actions": [],
                "grounded": False,
                "grounding_status": "permission_changed",
            }
        )
    return MessageOut(
        id=message.id,
        conversation_id=message.conversation_id,
        role=message.role.value,
        content=content,
        payload=payload,
        created_at=_iso(message.created_at),
    )


def to_summary(conversation: Conversation, message_count: int) -> ConversationSummary:
    return ConversationSummary(
        id=conversation.id,
        title=conversation.title,
        message_count=message_count,
        created_at=_iso(conversation.created_at),
        updated_at=_iso(conversation.updated_at),
    )


def hydrated_message(
    session: DbSession,
    message: Message,
    knowledge: KnowledgeService,
    user: CurrentUser,
    requested_reference: str | None = None,
) -> MessageOut:
    task_id = (message.payload or {}).get("workflow_task_id")
    task = session.get(WorkflowTask, task_id) if task_id else None
    reference = task.ticket_reference if task else (message.payload or {}).get("ticket_reference")
    ticket = (
        session.scalar(select(Ticket).where(Ticket.reference == reference)) if reference else None
    )
    return to_message_out(
        message,
        knowledge.index.authorized_document_ids(user.role),
        requested_reference,
        task,
        ticket,
    )


@router.get(
    "/conversations",
    response_model=ConversationListResponse,
    summary="List the caller's conversations",
)
def list_conversations(
    request: Request, user: CurrentUser, session: DbSession
) -> ConversationListResponse:
    chat = get_chat_service(request)
    conversations = chat.list_conversations(session, user=user)
    summaries = [
        to_summary(conversation, chat.message_count(session, conversation.id))
        for conversation in conversations
    ]
    return ConversationListResponse(count=len(summaries), conversations=summaries)


@router.post(
    "/conversations",
    response_model=ConversationSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Start a new conversation",
)
def create_conversation(
    payload: CreateConversationRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> ConversationSummary:
    chat = get_chat_service(request)
    conversation = chat.create_conversation(session, user=user, title=payload.title)
    session.commit()
    return to_summary(conversation, 0)


@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationDetail,
    summary="Read one of the caller's conversations",
)
def get_conversation(
    conversation_id: int,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> ConversationDetail:
    chat = get_chat_service(request)
    conversation = chat.get_owned_conversation(session, user=user, conversation_id=conversation_id)
    messages = chat.list_messages(session, conversation)
    summary = to_summary(conversation, len(messages))
    linked: dict[int, str] = dict(
        session.execute(
            select(ManualTicketLink.message_id, Ticket.reference)
            .join(Ticket)
            .where(ManualTicketLink.message_id.in_([m.id for m in messages]))
        )
        .tuples()
        .all()
    )
    return ConversationDetail(
        **summary.model_dump(),
        messages=[
            hydrated_message(session, m, get_knowledge(request), user, linked.get(m.id))
            for m in messages
        ],
    )


@router.delete(
    "/conversations/{conversation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Delete one of the caller's conversations",
)
def delete_conversation(
    conversation_id: int,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> Response:
    chat = get_chat_service(request)
    chat.delete_conversation(session, user=user, conversation_id=conversation_id)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=PostMessageResponse,
    summary="Send a message and receive a grounded answer with citations",
)
def post_message(
    conversation_id: int,
    payload: PostMessageRequest,
    request: Request,
    user: CurrentUser,
    session: DbSession,
    settings: AppSettings,
) -> PostMessageResponse:
    chat = get_chat_service(request)
    conversation = chat.get_owned_conversation(session, user=user, conversation_id=conversation_id)

    # Throttle before doing any expensive work (embedding, search, model call).
    message_limiter(request, settings).check(f"chat:{user.id}")

    request_record = None
    if payload.client_request_id:
        now = dt.datetime.now(dt.UTC)
        lease_until = now + dt.timedelta(
            seconds=4 * settings.llm_timeout_seconds * (settings.llm_max_retries + 1) + 30
        )
        question_hash = hashlib.sha256(
            redact_credentials(payload.content).encode("utf-8")
        ).hexdigest()
        statement = select(ChatRequest).where(
            ChatRequest.user_id == user.id,
            ChatRequest.conversation_id == conversation_id,
            ChatRequest.request_key == payload.client_request_id,
        )
        request_record = session.scalar(statement)
        if request_record is None:
            request_record = ChatRequest(
                user_id=user.id,
                conversation_id=conversation_id,
                request_key=payload.client_request_id,
                question_hash=question_hash,
                actor_role=user.role.value,
                pending_content=redact_credentials(payload.content),
                lease_until=lease_until,
            )
            session.add(request_record)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                raise ChatInProgressError() from None
        else:
            if (
                request_record.question_hash != question_hash
                or request_record.actor_role != user.role.value
            ):
                raise ValidationError("This request key belongs to a different message or role.")
            if request_record.response is not None:
                result = PostMessageResponse(**request_record.response)
                allowed = get_knowledge(request).index.authorized_document_ids(user.role)
                if result.assistant_message.payload and any(
                    source.document_id not in allowed
                    for source in result.assistant_message.payload.source_documents
                ):
                    raise ValidationError(
                        "Your document permissions changed. Use a new request key."
                    )
                assistant = session.get(Message, result.assistant_message.id)
                if assistant is not None:
                    result.assistant_message = hydrated_message(
                        session, assistant, get_knowledge(request), user
                    )
                return result
            reclaimed = session.scalar(
                update(ChatRequest)
                .where(
                    ChatRequest.id == request_record.id,
                    ChatRequest.response.is_(None),
                    ChatRequest.lease_until < now,
                )
                .values(lease_until=lease_until)
                .execution_options(synchronize_session="fetch")
                .returning(ChatRequest.id)
            )
            session.commit()
            if reclaimed is None:
                raise ChatInProgressError()

    record_audit(
        session,
        action=AuditAction.QUERY_RECEIVED,
        actor=user,
        resource_type="conversation",
        resource_id=conversation.id,
        detail={"role": user.role.value, "question_chars": len(payload.content)},
        ip_address=client_ip(request),
    )

    claimed_lease = request_record.lease_until if request_record is not None else None

    with model_budget(
        settings.chat_model_deadline_seconds,
        settings.chat_max_model_api_calls,
        settings.chat_max_output_tokens,
    ) as usage:
        user_message, assistant_message, generated, analysis = chat.post_message(
            session,
            user=user,
            conversation=conversation,
            content=payload.content,
            request_record=request_record,
        )
    assistant_message.payload = {**(assistant_message.payload or {}), "model_usage": usage.metadata()}

    record_audit(
        session,
        action=AuditAction.QUERY_ANSWERED,
        actor=user,
        resource_type="conversation",
        resource_id=conversation.id,
        detail={
            **generated.retrieval.audit_detail(),
            "provider": generated.provider,
            "model_usage": usage.metadata(),
            "grounded": generated.grounded,
            "answer_chars": len(generated.answer),
            **analysis.audit_detail(),
        },
        ip_address=client_ip(request),
    )
    if analysis.blocked:
        record_audit(
            session,
            action=AuditAction.QUERY_BLOCKED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail=analysis.guard.audit_detail(),
            ip_address=client_ip(request),
        )
    if analysis.requires_escalation:
        # Creating the ticket is Phase 6's job. Recording the decision now means
        # the security team has the signal even if ticket creation later fails.
        record_audit(
            session,
            action=AuditAction.ESCALATION_TRIGGERED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail={
                "risk_level": analysis.risk.level.value,
                "signals": [signal.label for signal in analysis.risk.signals],
                "reason": analysis.risk.reason,
            },
            ip_address=client_ip(request),
        )
    if generated.retrieval.dropped_unauthorized:
        record_audit(
            session,
            action=AuditAction.RETRIEVAL_DENIED,
            outcome=AuditOutcome.DENIED,
            actor=user,
            resource_type="conversation",
            resource_id=conversation.id,
            detail={"dropped_unauthorized": generated.retrieval.dropped_unauthorized},
            ip_address=client_ip(request),
        )
    session.refresh(user)
    allowed = get_knowledge(request).index.authorized_document_ids(user.role)
    result = PostMessageResponse(
        conversation_id=conversation.id,
        user_message=to_message_out(user_message, allowed),
        assistant_message=to_message_out(assistant_message, allowed),
    )
    if request_record is not None:
        saved = session.scalar(
            update(ChatRequest)
            .where(
                ChatRequest.id == request_record.id,
                ChatRequest.response.is_(None),
                ChatRequest.lease_until == claimed_lease,
            )
            .values(response=result.model_dump(), lease_until=None)
            .execution_options(synchronize_session="fetch")
            .returning(ChatRequest.id)
        )
        if saved is None:
            session.rollback()
            raise ChatInProgressError()
    session.commit()
    return result


class ChatInProgressError(AppError):
    status_code = 409
    code = "chat_in_progress"
    message = "This message is already being processed. Retry with the same request key shortly."


@router.get(
    "/capabilities",
    summary="What the assistant can currently do, for the calling role",
)
def capabilities(request: Request, user: CurrentUser, settings: AppSettings) -> dict[str, Any]:
    """Describes the assistant to the UI without exposing any configuration secret.

    Authenticated callers get the operational picture the footer and the sidebar
    need - which generator is answering, and which index is being searched. The
    *counts* inside the pipeline description (guard rules, intent rules, risk rules,
    the confidence threshold) are visible only to the security role: they describe
    the size of the pattern-matching gate and where its threshold sits, which is a
    map for anyone trying to get past it, and no other role needs them to use the
    product.
    """
    chat = get_chat_service(request)
    knowledge = get_knowledge(request)
    from app.security.rbac import describe_role

    scope = describe_role(user.role, knowledge.index.documents)
    detailed = user.role is Role.SECURITY
    return {
        "role": user.role.value,
        "demo_enabled": settings.demo_login_enabled,
        "role_label": user.role.label,
        "scope_description": scope["description"],
        "document_count": scope["document_count"],
        "provider": chat.describe_provider(),
        "pipeline": describe_pipeline_for(chat.describe_pipeline(), detailed=detailed),
        "knowledge_ready": knowledge.is_ready(),
        "categories": knowledge.categories(user.role),
        "retrieval": {
            "vector_store": settings.vector_store,
            "top_k": settings.retrieval_top_k,
        },
    }


def describe_pipeline_for(pipeline: dict[str, Any], *, detailed: bool) -> dict[str, Any]:
    """The pipeline description, with the rule counts removed for non-security roles.

    Kept as a function rather than a comprehension so the reduction is explicit and
    testable: everything an ordinary role receives is a capability flag, never a
    count.
    """
    if detailed:
        return pipeline

    guard = pipeline.get("guard", {})
    intent = pipeline.get("intent", {})
    risk = pipeline.get("risk", {})
    return {
        "guard": {"enabled": guard.get("enabled", False)},
        "intent": {"model_available": intent.get("model_available", False)},
        # Which levels a human is called for is published policy (KB-009), so it
        # stays: a user needs it to understand why they were escalated.
        "risk": {"escalation_levels": risk.get("escalation_levels", [])},
        "workflow": pipeline.get("workflow", {}),
    }
