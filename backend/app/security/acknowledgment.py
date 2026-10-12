"""One human-response definition for ticket detail and aggregate metrics."""

from sqlalchemy import and_, func, select
from sqlalchemy.orm import aliased

from app.db.models import Ticket, TicketEvent

REVIEW_ROLES = ("it", "security")
RESPONSE_EVENTS = ("status_changed", "note")


def human_response_predicate():
    return and_(
        TicketEvent.automated.is_(False),
        TicketEvent.actor_role.in_(REVIEW_ROLES),
        TicketEvent.event_type.in_(RESPONSE_EVENTS),
    )


def incident_time_expression():
    """Current severity's latest recorded transition, including pre-outbox tickets."""
    transition = aliased(TicketEvent)
    latest = (
        select(func.max(transition.created_at))
        .where(transition.ticket_id == Ticket.id, transition.to_severity == Ticket.severity)
        .correlate(Ticket)
        .scalar_subquery()
    )
    return func.coalesce(latest, Ticket.created_at)


def response_absent_predicate():
    return (
        ~select(TicketEvent.id)
        .where(
            TicketEvent.ticket_id == Ticket.id,
            TicketEvent.created_at >= incident_time_expression(),
            human_response_predicate(),
        )
        .correlate(Ticket)
        .exists()
    )


def is_human_response(event: TicketEvent) -> bool:
    return (
        not event.automated
        and event.actor_role in REVIEW_ROLES
        and event.event_type in RESPONSE_EVENTS
    )
