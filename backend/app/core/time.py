"""SQLite returns naive datetimes; stored timestamps in this app are UTC."""

import datetime as dt
from typing import Any


def iso_utc(value: Any) -> str | None:
    if isinstance(value, dt.datetime):
        return (
            value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value.astimezone(dt.UTC)
        ).isoformat()
    return value.isoformat() if hasattr(value, "isoformat") else None
