"""Production-config API recovery drill; simulated users/data, offline model only.

Uses an in-process API client and an actual local TLS notification receiver.
This does not establish container, frontend TLS, real recipients or real
provider acceptance. Signing secrets are never reported.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))


def run(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    from scripts.notification_test_receiver import receiver

    notification_secret = secrets.token_urlsafe(48)
    receiver_context = receiver(output / "local-tls-receiver", notification_secret)
    endpoint = receiver_context.__enter__()
    source, snapshot, restored = [
        output / name for name in ("source.db", "backup.db", "restored.db")
    ]
    password = secrets.token_urlsafe(24)
    overrides = {
        "APP_ENV": "production",
        "DEBUG": "false",
        "LOG_LEVEL": "ERROR",
        "AUTH_SECRET_KEY": secrets.token_urlsafe(48),
        "ALLOW_DEMO_LOGIN": "false",
        "SEED_DEMO_USERS": "false",
        "DEMO_USER_PASSWORD": "SyntheticUnusedPassword#2026",
        "PASSWORD_HASH_ROUNDS": "12",
        "API_CORS_ORIGINS": "https://synthetic-pilot.example.com",
        "DATABASE_URL": "sqlite:///" + source.as_posix(),
        "KB_DIR": str(BACKEND / "knowledge_base"),
        "VECTOR_STORE": "memory",
        "VECTOR_STORE_PATH": str(output / "index"),
        "LLM_PROVIDER": "mock",
        "LLM_API_KEY": "",
        "EMBEDDING_PROVIDER": "tfidf",
        "EMBEDDING_API_KEY": "",
        "SHARED_SECURITY_LIMITS": "true",
        "WORKFLOW_RETRY_INTERVAL_SECONDS": "1",
        "MAINTENANCE_INTERVAL_SECONDS": "1",
        "RETENTION_POLICY_FILE": "",
        "RETENTION_BACKUP_DIR": "",
        "NOTIFICATION_WEBHOOK_URL": endpoint["primary_url"],
        "NOTIFICATION_LEAD_WEBHOOK_URL": endpoint["lead_url"],
        "NOTIFICATION_SIGNING_SECRET": notification_secret,
        "NOTIFICATION_CA_BUNDLE_FILE": endpoint["ca_file"],
        "NOTIFICATION_POLL_INTERVAL_SECONDS": "1",
    }
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    from app.core.config import get_settings
    from app.db.session import get_engine, reset_engine_cache

    get_settings.cache_clear()
    reset_engine_cache()
    try:
        from fastapi.testclient import TestClient
        from sqlalchemy import func, select
        from sqlalchemy.orm import Session

        from app.core.enums import Role
        from app.core.security import hash_password
        from app.db.migrations import current_revision, head_revision, upgrade_database
        from app.db.models import Ticket, User, WorkflowTask
        from app.main import create_app

        settings = get_settings()
        upgrade_database(get_engine(settings))  # Operator migration before production startup.
        with Session(get_engine(settings)) as session:
            for role in (Role.EMPLOYEE, Role.SECURITY):
                session.add(
                    User(
                        email=f"pilot-{role.value}@example.com",
                        full_name=f"Simulated Pilot {role.value}",
                        password_hash=hash_password(password),
                        role=role,
                    )
                )
            session.commit()
        app = create_app(settings)
        headers = {}
        with TestClient(app, raise_server_exceptions=False) as client:
            assert client.get("/docs").status_code == 404
            assert client.get("/api/v1/meta").json()["features"]["demo_login"] is False
            for role in ("employee", "security"):
                authenticated = client.post(
                    "/api/v1/auth/login",
                    json={"email": f"pilot-{role}@example.com", "password": password},
                )
                authenticated.raise_for_status()
                headers[role] = {"Authorization": "Bearer " + authenticated.json()["access_token"]}
            assert (
                client.get(
                    "/api/v1/knowledge/documents/KB-004", headers=headers["employee"]
                ).status_code
                == 404
            )
            created = client.post(
                "/api/v1/chat/conversations", headers=headers["employee"], json={}
            )
            created.raise_for_status()
            cid = created.json()["id"]
            sink = app.state.chat._workflow.tickets
            original = sink.create_ticket

            def failed_sink(*_args, **_kwargs):
                raise RuntimeError("synthetic ticket failure for recovery drill")

            sink.create_ticket = failed_sink
            try:
                reported = client.post(
                    f"/api/v1/chat/conversations/{cid}/messages",
                    headers=headers["employee"],
                    json={
                        "content": "我在钓鱼页面提交了验证码。",
                        "client_request_id": "synthetic-pilot-recovery",
                    },
                )
                reported.raise_for_status()
                payload = reported.json()["assistant_message"]["payload"]
                assert payload["human_escalation"] and payload["workflow_status"] == "pending"
                assert payload["ticket_reference"] is None
                task_id = payload["workflow_task_id"]
            finally:
                # Keep the failure active until the lifespan has stopped below;
                # restore only the instance method, not a global service class.
                pass
        sink.create_ticket = original
        reset_engine_cache()
        specification = importlib.util.spec_from_file_location(
            "ops_backup", ROOT / "scripts" / "ops-backup.py"
        )
        assert specification and specification.loader
        operation = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(operation)
        operation.backup(source, snapshot)
        operation.restore(snapshot, restored)
        os.environ["DATABASE_URL"] = "sqlite:///" + restored.as_posix()
        get_settings.cache_clear()
        reset_engine_cache()
        recovered = get_settings()
        with TestClient(create_app(recovered), raise_server_exceptions=False) as client:
            assert client.get("/api/v1/ready").status_code == 200
            assert client.get("/api/v1/auth/me", headers=headers["employee"]).status_code == 200
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                with Session(get_engine(recovered)) as session:
                    task = session.get(WorkflowTask, task_id)
                    if task and task.status == "completed":
                        reference = task.ticket_reference
                        assert (
                            session.scalar(
                                select(func.count(Ticket.id)).where(Ticket.conversation_id == cid)
                            )
                            == 1
                        )
                        break
                time.sleep(0.05)
            else:
                raise AssertionError(
                    "Restored application worker did not recover the pending incident"
                )
            history = client.get(f"/api/v1/chat/conversations/{cid}", headers=headers["employee"])
            history.raise_for_status()
            assert history.json()["messages"][-1]["payload"]["ticket_reference"] == reference
            assert (
                client.get(
                    "/api/v1/knowledge/documents/KB-004", headers=headers["employee"]
                ).status_code
                == 404
            )
            assert (
                client.get("/api/v1/tickets/workflows", headers=headers["employee"]).status_code
                == 403
            )
            retried = client.post(
                f"/api/v1/tickets/workflows/{task_id}/retry", headers=headers["security"], json={}
            )
            retried.raise_for_status()
            with Session(get_engine(recovered)) as session:
                assert (
                    session.scalar(
                        select(func.count(Ticket.id)).where(Ticket.conversation_id == cid)
                    )
                    == 1
                )
                assert session.scalar(select(func.count(User.id))) == 2  # No demo seeding.
            revision = current_revision(get_engine(recovered))
            assert revision == head_revision()
            delivered = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with closing(sqlite3.connect(endpoint["database"])) as receipt_db:
                    events = [
                        json.loads(row[0])
                        for row in receipt_db.execute("SELECT payload FROM receipts")
                    ]
                if any(
                    event["ticket_reference"] == reference and event["kind"] == "incident"
                    for event in events
                ):
                    delivered = True
                    break
                time.sleep(0.05)
            assert delivered, "Recovered worker did not notify the local TLS receiver"
        digest = hashlib.sha256()
        for path in sorted((BACKEND / "app").rglob("*.py")):
            digest.update(path.relative_to(BACKEND).as_posix().encode())
            digest.update(path.read_bytes())
        report = {
            "status": "passed",
            "mode": "production configuration; offline model; simulated data",
            "transport": "in-process TestClient; TLS/container acceptance not performed",
            "notification_transport": "local TLS receiver with certificate verification; not a formal recipient",
            "source_sha256": digest.hexdigest(),
            "migration_revision": revision,
            "checks": [
                "operator_migration",
                "demo_disabled",
                "only_provisioned_users",
                "failure_recorded_as_pending",
                "backup_restore",
                "session_survives_restore",
                "actual_worker_recovers_after_restore",
                "one_ticket_after_retry",
                "history_state_updates",
                "rbac_survives_restore",
                "business_readiness",
                "restored_notification_worker_delivery",
            ],
            "remaining": [
                "external_notification",
                "real_provider",
                "TLS",
                "container",
                "release_rollback",
                "production_secret_store_recovery",
            ],
        }
        (output / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return report
    finally:
        reset_engine_cache()
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
        receiver_context.__exit__(None, None, None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.output.resolve())
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "passed" else 1)
