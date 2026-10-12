"""Actual separate-process A/B/restore/A drill with two verified local releases.

Synthetic SQLite data, offline models, loopback HTTP API and local TLS receiver.
Does not validate Docker, public frontend TLS, formal recipients or real models.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import secrets
import socket
import sqlite3
import subprocess
import sys
import time
from contextlib import closing, contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

PREPARE = r"""
import json, os, time
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.core.enums import Role
from app.core.security import hash_password
from app.db.session import get_engine
from app.db.migrations import upgrade_database, current_revision
from app.db.models import User, NotificationOutbox, WorkflowTask
from app.main import create_app
cfg = get_settings()
upgrade_database(get_engine(cfg))
with Session(get_engine(cfg)) as session:
    for role in [Role.EMPLOYEE, Role.SECURITY]:
        session.add(User(email='release-'+role.value+'@example.com', full_name='Synthetic Release',
            password_hash=hash_password(os.environ['ESAA_DRILL_PASSWORD']), role=role))
    session.commit()
app = create_app(cfg)
with TestClient(app) as client:
    headers = {}
    for role in ['employee', 'security']:
        login = client.post('/api/v1/auth/login', json={'email':'release-'+role+'@example.com',
            'password':os.environ['ESAA_DRILL_PASSWORD']})
        login.raise_for_status()
        headers[role] = {'Authorization':'Bearer '+login.json()['access_token']}
    conversation = client.post('/api/v1/chat/conversations', headers=headers['employee'], json={}).json()['id']
    answer = client.post(f'/api/v1/chat/conversations/{conversation}/messages', headers=headers['employee'],
        json={'content':'我在钓鱼页面提交了验证码。','client_request_id':'release-first-event'})
    answer.raise_for_status()
    reference = answer.json()['assistant_message']['payload']['ticket_reference']
    assert reference
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        with Session(get_engine(cfg)) as session:
            alert = session.scalar(select(NotificationOutbox).where(NotificationOutbox.ticket_reference==reference))
            if alert and alert.status=='delivered':
                alert_id, event_key = alert.id, alert.event_key
                break
        time.sleep(.05)
    else:
        raise AssertionError('First actual TLS receipt not committed')
    pending_conversation = client.post('/api/v1/chat/conversations', headers=headers['employee'], json={}).json()['id']
    def failing_sink(*args, **kwargs):
        raise RuntimeError('Synthetic release-drill ticket sink failure')
    app.state.chat._workflow.tickets.create_ticket = failing_sink
    pending = client.post(f'/api/v1/chat/conversations/{pending_conversation}/messages', headers=headers['employee'],
        json={'content':'我在钓鱼页面提交了验证码。','client_request_id':'release-pending-event'})
    pending.raise_for_status()
    payload = pending.json()['assistant_message']['payload']
    assert payload['workflow_status']=='pending' and payload['ticket_reference'] is None
    task_id = payload['workflow_task_id']
print(json.dumps({'headers':headers,'conversation':conversation,'pending_conversation':pending_conversation,
    'task_id':task_id,'reference':reference,'alert_id':alert_id,'event_key':event_key,
    'revision':current_revision(get_engine(cfg))}))
"""

REPLAY = r"""
import os
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.db.session import get_engine
from app.db.models import NotificationOutbox, WorkflowTask
with Session(get_engine(get_settings())) as session:
    assert session.get(WorkflowTask, os.environ['ESAA_DRILL_TASK']).status=='pending'
    alert = session.get(NotificationOutbox, os.environ['ESAA_DRILL_ALERT'])
    assert alert.status=='delivered'
    # Simulate crash after receiver acknowledgment before durable sender acknowledgment.
    alert.status, alert.delivered_at, alert.lease_until = 'pending', None, None
    session.commit()
"""


def child(code: str, environment: dict, directory: Path) -> str:
    result = subprocess.run(  # noqa: S603 -- fixed interpreter, isolated release and synthetic environment
        [sys.executable, "-c", code],
        env=environment,
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode:
        raise RuntimeError("Isolated release preparation failed.")
    # Child application diagnostics can precede its final structured result.
    return result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""


@contextmanager
def server(environment: dict, directory: Path, log: Path, *, expected_ready: int):
    import httpx

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with log.open("xb") as output:
        process = subprocess.Popen(  # noqa: S603 -- owned child only, loopback, no shell
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-access-log",
            ],
            env=environment,
            cwd=directory,
            stdout=output,
            stderr=output,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}/api/v1", trust_env=False, timeout=5
            ) as client:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("Owned release process exited during startup.")
                    try:
                        response = client.get("/ready")
                        if response.status_code == expected_ready:
                            break
                    except httpx.TransportError:
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("Expected release readiness was not observed.")
                yield client
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def run(output: Path, previous: Path, candidate: Path) -> dict:
    from scripts.notification_test_receiver import receiver

    from app.db.backup import backup, restore, sha256

    spec = importlib.util.spec_from_file_location(
        "release_artifacts", ROOT / "scripts/ops-release.py"
    )
    assert spec and spec.loader
    releases = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(releases)
    output.mkdir(parents=True, exist_ok=False)
    old, new = output / "release-a", output / "release-b"
    old_summary = releases.verify(previous, old)
    new_summary = releases.verify(candidate, new)
    if old_summary["source_sha256"] == new_summary["source_sha256"]:
        raise ValueError("Two different release artifacts are required.")
    source, frozen, recovered = [
        output / name for name in ("source.db", "frozen.db", "recovered.db")
    ]
    signing_key = secrets.token_urlsafe(48)
    with receiver(output / "receiver", signing_key) as endpoint:
        base = dict(os.environ)
        base.update(
            {
                "APP_ENV": "production",
                "DEBUG": "false",
                "LOG_LEVEL": "ERROR",
                "AUTH_SECRET_KEY": secrets.token_urlsafe(48),
                "ALLOW_DEMO_LOGIN": "false",
                "SEED_DEMO_USERS": "false",
                "DEMO_USER_PASSWORD": "SyntheticUnusedPassword#2026",
                "PASSWORD_HASH_ROUNDS": "12",
                "API_CORS_ORIGINS": "https://synthetic-release.invalid",
                "DATABASE_URL": "sqlite:///" + source.as_posix(),
                "VECTOR_STORE": "memory",
                "VECTOR_STORE_PATH": str(output / "index"),
                "LLM_PROVIDER": "mock",
                "LLM_API_KEY": "",
                "EMBEDDING_PROVIDER": "tfidf",
                "EMBEDDING_API_KEY": "",
                "SHARED_SECURITY_LIMITS": "true",
                "WORKFLOW_RETRY_INTERVAL_SECONDS": "3600",
                "MAINTENANCE_INTERVAL_SECONDS": "3600",
                "RETENTION_POLICY_FILE": "",
                "RETENTION_BACKUP_DIR": "",
                "NOTIFICATION_WEBHOOK_URL": endpoint["primary_url"],
                "NOTIFICATION_LEAD_WEBHOOK_URL": endpoint["lead_url"],
                "NOTIFICATION_SIGNING_SECRET": signing_key,
                "NOTIFICATION_CA_BUNDLE_FILE": endpoint["ca_file"],
                "NOTIFICATION_POLL_INTERVAL_SECONDS": "1",
                "ESAA_DRILL_PASSWORD": secrets.token_urlsafe(24),
            }
        )

        def environment(directory, **changes):
            return {
                **base,
                "PYTHONPATH": str(directory / "backend"),
                "KB_DIR": str(directory / "backend/knowledge_base"),
                **changes,
            }

        env_a = environment(old)
        state = json.loads(child(PREPARE, env_a, old))
        with server(env_a, old, output / "a-before.log", expected_ready=200) as client:
            assert client.get("/auth/me", headers=state["headers"]["employee"]).status_code == 200
            assert (
                client.get(
                    "/knowledge/documents/KB-004", headers=state["headers"]["employee"]
                ).status_code
                == 404
            )
            assert (
                client.get("/tickets/workflows", headers=state["headers"]["security"]).status_code
                == 200
            )
        # All writers are stopped; fixture metadata edit belongs to the frozen baseline.
        child(
            REPLAY,
            {**env_a, "ESAA_DRILL_TASK": state["task_id"], "ESAA_DRILL_ALERT": state["alert_id"]},
            old,
        )
        before = backup(source, frozen)
        baseline_sha = sha256(source)
        env_b = environment(new)
        migrated = child(
            "from app.core.config import get_settings; from app.db.session import get_engine; from app.db.migrations import upgrade_database,current_revision; e=get_engine(get_settings()); upgrade_database(e); print(current_revision(e))",
            env_b,
            new,
        )
        assert migrated != state["revision"]
        invalid = output / "invalid-kb"
        invalid.mkdir()
        (invalid / "invalid.md").write_text("Synthetic deployment fault: required metadata absent")
        with server(
            {**env_b, "KB_DIR": str(invalid)}, new, output / "b-rejected.log", expected_ready=503
        ) as client:
            assert client.get("/health").status_code == 200
            assert client.get("/ready").json()["checks"]["knowledge_base"] != "ok"
        assert not recovered.exists()
        restore(frozen, recovered)
        env_restored = environment(
            old,
            DATABASE_URL="sqlite:///" + recovered.as_posix(),
            WORKFLOW_RETRY_INTERVAL_SECONDS="1",
        )
        with server(env_restored, old, output / "a-restored.log", expected_ready=200) as client:
            headers = state["headers"]
            assert client.get("/auth/me", headers=headers["employee"]).status_code == 200
            assert (
                client.get("/knowledge/documents/KB-004", headers=headers["employee"]).status_code
                == 404
            )
            assert client.get("/tickets/workflows", headers=headers["employee"]).status_code == 403
            assert (
                client.get(
                    "/tickets/" + state["reference"], headers=headers["security"]
                ).status_code
                == 200
            )
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with closing(sqlite3.connect(recovered)) as database:
                    task = database.execute(
                        "SELECT status,ticket_reference FROM workflow_tasks WHERE id=?",
                        (state["task_id"],),
                    ).fetchone()
                    notification = database.execute(
                        "SELECT status FROM notification_outbox WHERE id=?", (state["alert_id"],)
                    ).fetchone()
                    recovered_alert = database.execute(
                        "SELECT status FROM notification_outbox WHERE ticket_reference=?",
                        (task[1],),
                    ).fetchone()
                if (
                    task[0] == "completed"
                    and notification[0] == "delivered"
                    and recovered_alert is not None
                    and recovered_alert[0] == "delivered"
                ):
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("Restored workers did not finish persisted work.")
            response = client.post(
                "/tickets/workflows/" + state["task_id"] + "/retry",
                headers=headers["security"],
                json={},
            )
            response.raise_for_status()
            history = client.get(
                f"/chat/conversations/{state['pending_conversation']}", headers=headers["employee"]
            )
            history.raise_for_status()
            assert history.json()["messages"][-1]["payload"]["ticket_reference"] == task[1]
            with closing(sqlite3.connect(recovered)) as database:
                assert (
                    database.execute(
                        "SELECT COUNT(*) FROM tickets WHERE conversation_id=?",
                        (state["pending_conversation"],),
                    ).fetchone()[0]
                    == 1
                )
                assert (
                    database.execute("SELECT version_num FROM alembic_version").fetchone()[0]
                    == state["revision"]
                )
                assert database.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
        with closing(sqlite3.connect(endpoint["database"])) as database:
            assert (
                database.execute(
                    "SELECT COUNT(*) FROM receipts WHERE id=?", (state["alert_id"],)
                ).fetchone()[0]
                == 1
            )
            assert database.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 2
        assert endpoint["requests"] >= 3 and endpoint["signature_errors"] == 0
        # Migration touched only the candidate source; recovery used a distinct new file.
        assert source.exists() and sha256(frozen) == before["database_sha256"]
        report = {
            "status": "passed",
            "scope": "separate-process local release rollback; synthetic data; mock/TF-IDF",
            "api_transport": "actual loopback HTTP; public TLS and browser not validated",
            "notification_transport": "actual local TLS with certificate verification and persistent receiver deduplication",
            "release_a": old_summary,
            "release_b": new_summary,
            "revision_before": state["revision"],
            "revision_candidate": migrated,
            "revision_restored": state["revision"],
            "baseline_database_sha256": baseline_sha,
            "backup_sha256": before["database_sha256"],
            "checks": [
                "distinct_verified_artifacts",
                "a_actual_api",
                "frozen_writes",
                "candidate_operator_migration",
                "candidate_readiness_failure",
                "restore_to_fresh_file",
                "old_build_restarted",
                "old_sessions_preserved",
                "rbac_preserved",
                "unique_pending_ticket_recovered",
                "history_repaired",
                "receiver_replay_deduplicated",
            ],
            "data_loss": "No new business writes after freeze. Candidate operational acknowledgments discarded on restore; receiver deduplication verified.",
            "remaining": [
                "Docker release images",
                "formal recipients",
                "frontend/public TLS",
                "secret store recovery",
                "real providers",
            ],
        }
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run(args.output.resolve(), args.previous.resolve(), args.candidate.resolve())
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__}
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["status"] == "passed" else 1)
