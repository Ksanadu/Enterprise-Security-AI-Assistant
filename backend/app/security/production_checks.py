"""Production refuses prototype accounts and incomplete response infrastructure."""

from urllib.parse import urlsplit

from sqlalchemy import select

from app.core.config import Settings
from app.db.models import User
from app.db.session import get_session_factory

DEMO_EMAILS = (
    "employee@example.com",
    "employee2@example.com",
    "it@example.com",
    "security@example.com",
)


def validate_notification_configuration(settings: Settings) -> bool:
    urls = (settings.notification_webhook_url, settings.notification_lead_webhook_url)
    if not settings.notification_webhook_url:
        if settings.is_production:
            raise RuntimeError("Production requires a configured notification receiver.")
        return False
    if len(settings.notification_signing_secret) < 32:
        raise RuntimeError("Notification signing secret must contain at least 32 characters.")
    for url in urls:
        if not url:
            continue
        parsed = urlsplit(url)
        if (
            parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
        ):
            raise RuntimeError("Notification URL must omit credentials, query and fragment.")
        if parsed.scheme != "https" and not (
            not settings.is_production
            and parsed.scheme == "http"
            and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        ):
            raise RuntimeError(
                "Notifications require HTTPS; development HTTP is limited to loopback."
            )
    if settings.is_production and (not urls[1] or settings.notification_poll_interval_seconds == 0):
        raise RuntimeError("Production requires a lead receiver and active delivery worker.")
    return True


def check_production(settings: Settings) -> None:
    validate_notification_configuration(settings)
    if not settings.is_production:
        return
    with get_session_factory(settings)() as session:
        if session.scalar(
            select(User.id).where(User.is_active.is_(True), User.email.in_(DEMO_EMAILS)).limit(1)
        ):
            raise RuntimeError(
                "Active prototype accounts exist; explicitly deactivate them before production startup."
            )
