"""Explicit role creation, real authentication, audit and credential failure privacy."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from scripts.provision_user import provision
from sqlalchemy import select

from app.db.models import AuditLog, User
from app.db.session import get_session_factory, init_db
from app.main import create_app

PASSWORD = "Synthetic#Credential2026"


@pytest.mark.parametrize("role", ["employee", "it", "security"])
def test_explicit_account_is_backed_up_audited_and_has_real_role_scope(settings, tmp_path, role):
    settings.seed_demo_users = settings.allow_demo_login = False
    init_db(settings)
    identity = f"new-{role}@example.com"
    assert provision(identity, "New Admin", role)["status"] == "dry_run"
    with get_session_factory(settings)() as session:
        assert session.scalar(select(User.id)) is None
    backup = tmp_path / "before-account.db"
    created = provision(
        identity, "New Admin", role, apply=True, password=PASSWORD, backup_path=backup
    )
    assert created["role"] == role and created["backup_verified"] and backup.is_file()
    with get_session_factory(settings)() as session:
        user = session.scalar(select(User))
        assert user.password_hash != PASSWORD and user.email == identity
        audit = session.scalar(
            select(AuditLog).where(AuditLog.action == "production.user_provisioned")
        )
        assert audit.resource_id == str(user.id) and audit.detail["assigned_role"] == role
        assert PASSWORD not in json.dumps(audit.detail)
    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/api/v1/auth/login", json={"email": identity.upper(), "password": PASSWORD}
        )
        assert response.status_code == 200 and response.json()["user"]["role"] == role
        headers = {"Authorization": "Bearer " + response.json()["access_token"]}
        assert client.get("/api/v1/operations/status", headers=headers).status_code == (
            200 if role == "security" else 403
        )
    with pytest.raises(ValueError, match="already exists"):
        provision(
            identity.upper(),
            "Changed",
            "security",
            apply=True,
            password=PASSWORD,
            backup_path=tmp_path / "duplicate.db",
        )
    assert not (tmp_path / "duplicate.db").exists()


@pytest.mark.parametrize(
    "password", ["short1", "alllowercasepassword1", "New AdminPassword2026!", "汉字" * 30 + "A1!"]
)
def test_invalid_password_never_creates_account_or_backup(settings, tmp_path, password):
    init_db(settings)
    backup = tmp_path / "rejected.db"
    with pytest.raises(ValueError, match="Password"):
        provision(
            "fresh@example.com",
            "New Admin",
            "employee",
            apply=True,
            password=password,
            backup_path=backup,
        )
    assert not backup.exists()
    with get_session_factory(settings)() as session:
        assert session.scalar(select(User.id)) is None


def test_creation_refuses_prototype_and_missing_backup(settings):
    init_db(settings)
    with pytest.raises(ValueError, match="prototype"):
        provision("employee@example.com", "New Admin", "security")
    with pytest.raises(ValueError, match="backup"):
        provision("fresh@example.com", "New Admin", "security", apply=True, password=PASSWORD)


def test_cli_error_does_not_echo_secret_or_validation_input(settings, tmp_path):
    init_db(settings)
    marker = "SYNTHETIC-CREDENTIAL-MUST-NOT-BE-PRINTED"
    env = {**os.environ, "ESAA_INITIAL_PASSWORD": marker}
    completed = subprocess.run(  # noqa: S603 -- current Python and repository CLI
        [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "scripts" / "provision_user.py"),
            "--email",
            "fresh@example.com",
            "--name",
            "New Admin",
            "--role",
            "security",
            "--apply",
            "--backup",
            str(tmp_path / "unused.db"),
        ],
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 1
    assert marker not in completed.stdout + completed.stderr
    assert json.loads(completed.stdout)["error_type"] == "ValueError"
