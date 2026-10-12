"""Preview/create one explicitly assigned account; never modify an existing principal."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


def provision(
    email: str,
    full_name: str,
    role: str,
    *,
    apply: bool = False,
    password: str | None = None,
    backup_path: Path | None = None,
) -> dict:
    from pydantic import EmailStr, TypeAdapter
    from sqlalchemy import func, select

    from app.core.config import get_settings
    from app.core.enums import Role
    from app.core.security import BCRYPT_MAX_BYTES, hash_password, validate_password_strength
    from app.db.backup import backup
    from app.db.migrations import require_current_schema
    from app.db.models import AuditLog, User
    from app.db.session import get_engine, get_session_factory
    from app.security.production_checks import DEMO_EMAILS
    from app.services.retention import ERASED_PRINCIPAL

    normalized = str(TypeAdapter(EmailStr).validate_python(email)).strip().lower()
    assigned = Role(role)
    full_name = full_name.strip()
    if not full_name or len(full_name) > 160 or normalized in (*DEMO_EMAILS, ERASED_PRINCIPAL):
        raise ValueError("Use a non-prototype identity and a bounded display name.")
    settings = get_settings()
    database = settings.sqlite_path
    if database is None or not database.is_file():
        raise RuntimeError("Migrate an explicit SQLite database first.")
    require_current_schema(get_engine(settings))
    with get_session_factory(settings)() as session:
        duplicate = session.scalar(select(User.id).where(func.lower(User.email) == normalized))
    if duplicate is not None:
        raise ValueError(
            "An account already exists; creation never changes role, password or active state."
        )
    if not apply:
        return {"status": "dry_run", "role": assigned.value, "data_changed": False}
    categories = sum(
        (
            any(c.islower() for c in password or ""),
            any(c.isupper() for c in password or ""),
            any(c.isdigit() for c in password or ""),
            any(not c.isalnum() for c in password or ""),
        )
    )
    identity_words = [normalized.split("@")[0], *full_name.split()]
    if (
        password is None
        or len(password) < 14
        or len(password.encode()) > BCRYPT_MAX_BYTES
        or validate_password_strength(password)
        or password == settings.demo_user_password
        or categories < 3
        or any(len(word) >= 3 and word.casefold() in password.casefold() for word in identity_words)
    ):
        raise ValueError(
            "Password must satisfy policy, differ from demo credentials and fit bcrypt's byte bound."
        )
    if backup_path is None:
        raise ValueError("An explicit fresh backup is required.")
    backup(database, backup_path)
    hashed = hash_password(password, rounds=settings.password_hash_rounds)
    with get_session_factory(settings)() as session:
        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        if session.scalar(select(User.id).where(func.lower(User.email) == normalized)) is not None:
            raise ValueError("Account appeared concurrently; existing credentials unchanged.")
        user = User(email=normalized, full_name=full_name, role=assigned, password_hash=hashed)
        session.add(user)
        session.flush()
        # Fail creation if its audit cannot be committed; no partial account.
        session.add(
            AuditLog(
                created_at=dt.datetime.now(dt.UTC),
                action="production.user_provisioned",
                resource_type="user",
                resource_id=str(user.id),
                detail={"assigned_role": assigned.value, "origin": "operator_cli"},
            )
        )
        session.commit()
    return {
        "status": "created",
        "user_id": user.id,
        "role": assigned.value,
        "backup_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--role", choices=("employee", "it", "security"), required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup", type=Path)
    args = parser.parse_args()
    try:
        password = None
        if args.apply:
            password = os.environ.get("ESAA_INITIAL_PASSWORD")
            if password is None:
                if not sys.stdin.isatty():
                    raise ValueError("Noninteractive creation requires a secret environment value.")
                password = getpass.getpass("Initial password: ")
                if password != getpass.getpass("Repeat initial password: "):
                    raise ValueError("Password entries differ.")
        result = provision(
            args.email,
            args.name,
            args.role,
            apply=args.apply,
            password=password,
            backup_path=args.backup,
        )
        print(json.dumps(result))
        return 0
    except Exception as exc:
        # Validation/hash/database exception strings may include credential input.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
