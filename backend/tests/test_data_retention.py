"""Real erasure/restore, preservation, concurrency gates, API hiding and scheduling."""

import datetime as dt
import json
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.enums import MessageRole, Role, Severity, TicketStatus
from app.core.security import hash_password
from app.db.backup import backup, restore
from app.db.models import (
    AuditLog,
    ChatRequest,
    Conversation,
    DataHold,
    Message,
    NotificationOutbox,
    Ticket,
    User,
    WorkflowTask,
)
from app.db.session import get_engine, get_session_factory, init_db
from app.main import create_app
from app.services import retention
from app.services.retention import (
    backup_directory,
    prune_backups,
    read_policy,
    run_retention,
    set_hold,
)


def policy_config(settings, tmp_path, **changes):
    data = {
        "version": 1,
        "state": "approved",
        "policy_id": "synthetic-reviewed-policy",
        "approved_by": "Synthetic data owner",
        "conversations_days": 1,
        "closed_tickets_days": 1,
        "completed_workflows_days": 1,
        "audit_days": 1,
        "notifications_days": 1,
        "batch_limit": 200,
    }
    data.update(changes)
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(data), encoding="utf-8")
    return settings.model_copy(
        update={
            "retention_policy_file": str(policy),
            "retention_backup_dir": str(tmp_path / "backups"),
            "seed_demo_users": False,
            "allow_demo_login": False,
        }
    )


def seed(settings):
    init_db(settings)
    old = dt.datetime.now(dt.UTC) - dt.timedelta(days=30)
    with get_session_factory(settings)() as session:
        user = User(
            email="retention-owner@example.com",
            full_name="Synthetic Owner",
            role=Role.EMPLOYEE,
            password_hash=hash_password("Synthetic#Credential2026", rounds=4),
        )
        session.add(user)
        session.flush()
        conversation = Conversation(
            user_id=user.id,
            title="synthetic-private-title",
            peak_risk_level="high",
            created_at=old,
            updated_at=old,
        )
        session.add(conversation)
        session.flush()
        message = Message(
            conversation_id=conversation.id,
            role=MessageRole.USER,
            content="synthetic-private-message",
            payload={"synthetic_private": "material"},
            created_at=old,
            updated_at=old,
        )
        ticket = Ticket(
            reference="SEC-SYNTHETIC-RETAIN",
            title="synthetic-private-ticket",
            description="synthetic-private-description",
            related_query="synthetic-private-query",
            severity=Severity.HIGH,
            status=TicketStatus.RESOLVED,
            conversation_id=conversation.id,
            created_by_user_id=user.id,
            created_at=old,
            updated_at=old,
        )
        session.add_all([message, ticket])
        session.flush()
        task = WorkflowTask(
            id=str(uuid.uuid4()),
            status="completed",
            snapshot={"synthetic_private": "material"},
            ticket_reference=ticket.reference,
            conversation_id=conversation.id,
            user_message_id=message.id,
            created_at=old,
            updated_at=old,
        )
        alert = NotificationOutbox(
            id=str(uuid.uuid4()),
            event_key="synthetic-retention-event",
            ticket_id=ticket.id,
            ticket_reference=ticket.reference,
            severity="high",
            kind="incident",
            status="delivered",
            attempts=1,
            attempt_limit=10,
            created_at=old,
            delivered_at=old,
            next_attempt_at=old,
        )
        audit = AuditLog(
            action="chat.query.answered",
            actor_user_id=user.id,
            actor_email=user.email,
            resource_type="conversation",
            resource_id=str(conversation.id),
            detail={"synthetic_private": "material"},
            created_at=old,
        )
        session.add_all([task, alert, audit])
        session.commit()
        return {
            "user": user.id,
            "conversation": conversation.id,
            "message": message.id,
            "ticket": ticket.id,
            "workflow": task.id,
            "notification": alert.id,
            "audit": audit.id,
        }


def test_preview_erasure_backup_restore_hidden_api_and_nonreused_identifiers(settings, tmp_path):
    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    preview = run_retention(cfg)
    assert preview["counts"] == {
        "conversations": 1,
        "tickets": 1,
        "workflows": 1,
        "notifications": 1,
        "audit": 1,
    }
    assert not (tmp_path / "backups").exists()
    result = run_retention(cfg, apply=True)
    assert result["counts"] == preview["counts"] and result["backup_verified"]
    with get_session_factory(cfg)() as session:
        for kind, model in (
            ("conversation", Conversation),
            ("message", Message),
            ("ticket", Ticket),
            ("audit", AuditLog),
        ):
            assert session.scalar(select(model.id).where(model.id == ids[kind])) is None
        erased = session.scalar(
            select(Message)
            .where(Message.id == ids["message"])
            .execution_options(include_retention_records=True)
        )
        assert erased.content == "" and erased.payload is None
        assert session.get(WorkflowTask, ids["workflow"]) is None
        assert session.get(NotificationOutbox, ids["notification"]) is None
        principal = session.scalar(select(User).where(User.email == retention.ERASED_PRINCIPAL))
        assert principal and not principal.is_active
        new_conversation = Conversation(user_id=ids["user"], title="new")
        new_ticket = Ticket(reference="SEC-SYNTHETIC-NEW", title="new")
        session.add_all([new_conversation, new_ticket])
        session.flush()
        new_message = Message(
            conversation_id=new_conversation.id, role=MessageRole.USER, content="new"
        )
        session.add(new_message)
        session.commit()
        assert (
            new_conversation.id > ids["conversation"]
            and new_ticket.id > ids["ticket"]
            and new_message.id > ids["message"]
        )
    snapshot = next((tmp_path / "backups").glob("retention-*.db"))
    recovered = tmp_path / "recovered.db"
    assert restore(snapshot, recovered)["status"] == "restore_verified"
    recovered_cfg = cfg.model_copy(
        update={"database_url": "sqlite:///" + recovered.as_posix(), "retention_policy_file": ""}
    )
    with get_session_factory(recovered_cfg)() as session:
        assert session.get(Message, ids["message"]).content == "synthetic-private-message"
        assert session.get(Ticket, ids["ticket"]).description == "synthetic-private-description"
    with TestClient(create_app(cfg)) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"email": "retention-owner@example.com", "password": "Synthetic#Credential2026"},
        )
        headers = {"Authorization": "Bearer " + login.json()["access_token"]}
        assert (
            client.get(
                f"/api/v1/chat/conversations/{ids['conversation']}", headers=headers
            ).status_code
            == 404
        )
        assert (
            client.get("/api/v1/tickets/SEC-SYNTHETIC-RETAIN", headers=headers).status_code == 404
        )
        assert client.get("/api/v1/chat/conversations", headers=headers).json()["count"] == 1


@pytest.mark.parametrize("kind", ["conversation", "ticket", "audit"])
def test_preservation_hold_excludes_records_and_can_be_released(settings, tmp_path, kind):
    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    with get_session_factory(cfg)() as session:
        assert set_hold(session, kind, ids[kind], "CASE-SYNTHETIC")["status"] == "held"
        session.commit()
    preview = run_retention(cfg)["counts"]
    assert preview["audit"] == 0
    if kind in {"conversation", "ticket"}:
        assert not any(preview.values())
    with get_session_factory(cfg)() as session:
        set_hold(session, kind, ids[kind], "CASE-SYNTHETIC", release=True)
        session.commit()
    assert all(value == 1 for value in run_retention(cfg)["counts"].values())


@pytest.mark.parametrize(
    "condition",
    ["open_ticket", "pending_task", "failed_notification", "active_request", "unclaimed_request"],
)
def test_unfinished_work_and_active_request_are_preserved(settings, tmp_path, condition):
    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    with get_session_factory(cfg)() as session:
        if condition == "open_ticket":
            session.get(Ticket, ids["ticket"]).status = TicketStatus.ESCALATED
        elif condition == "pending_task":
            session.get(WorkflowTask, ids["workflow"]).status = "pending"
        elif condition == "failed_notification":
            session.get(NotificationOutbox, ids["notification"]).status = "exhausted"
        else:
            old = dt.datetime.now(dt.UTC) - dt.timedelta(days=30)
            session.add(
                ChatRequest(
                    user_id=ids["user"],
                    conversation_id=ids["conversation"],
                    request_key="synthetic-inflight",
                    question_hash="synthetic-hash",
                    actor_role="employee",
                    created_at=old,
                    updated_at=old,
                    lease_until=(
                        dt.datetime.now(dt.UTC) + dt.timedelta(minutes=1)
                        if condition == "active_request"
                        else None
                    ),
                )
            )
        session.commit()
    preview = run_retention(cfg)["counts"]
    if condition not in {"active_request", "unclaimed_request"}:
        assert preview["tickets"] == 0
    assert preview["conversations"] == 0


def test_backup_failure_prevents_erasure_and_hold_added_during_backup_wins(
    settings, tmp_path, monkeypatch
):
    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    original = retention.backup

    def failed(*_args):
        raise OSError("synthetic backup failure")

    monkeypatch.setattr(retention, "backup", failed)
    with pytest.raises(OSError):
        run_retention(cfg, apply=True)
    with get_session_factory(cfg)() as session:
        assert session.get(Message, ids["message"]).content == "synthetic-private-message"

    def preserve_during_backup(*args):
        result = original(*args)
        with get_session_factory(cfg)() as session:
            set_hold(session, "conversation", ids["conversation"], "CASE-ARRIVED-DURING-BACKUP")
            session.commit()
        return result

    monkeypatch.setattr(retention, "backup", preserve_during_backup)
    assert not any(run_retention(cfg, apply=True)["counts"].values())


def test_transaction_failure_rolls_back_all_erasure(settings, tmp_path, monkeypatch):
    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    original = retention.apply_plan

    def interrupted(session, selected, now):
        original(session, selected, now)
        raise RuntimeError("synthetic interrupted commit")

    monkeypatch.setattr(retention, "apply_plan", interrupted)
    with pytest.raises(RuntimeError):
        run_retention(cfg, apply=True)
    with get_session_factory(cfg)() as session:
        assert session.get(Message, ids["message"]).content == "synthetic-private-message"
        assert session.get(WorkflowTask, ids["workflow"]) is not None
        assert session.get(NotificationOutbox, ids["notification"]) is not None
    assert len(list((tmp_path / "backups").glob("retention-*.db"))) == 1


def test_running_scheduler_executes_approved_cleanup(settings, tmp_path):
    cfg = policy_config(settings, tmp_path)
    cfg.maintenance_interval_seconds = 1
    ids = seed(cfg)
    with TestClient(create_app(cfg)):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with get_session_factory(cfg)() as session:
                if (
                    session.scalar(
                        select(Conversation.id).where(Conversation.id == ids["conversation"])
                    )
                    is None
                ):
                    break
            time.sleep(0.02)
        else:
            raise AssertionError("Actual scheduler did not erase eligible data")
    assert list((tmp_path / "backups").glob("retention-*.db"))


def test_example_policy_is_refused_and_error_does_not_echo_input(settings, tmp_path):
    source = tmp_path / "unapproved.json"
    marker = "synthetic-private-policy-input"
    source.write_text(json.dumps({"state": "example_not_approved", "approved_by": marker}))
    with pytest.raises(RuntimeError) as error:
        read_policy(str(source))
    assert marker not in str(error.value)


def test_owner_cannot_delete_held_conversation_and_deleted_identifiers_stay_reserved(
    settings, tmp_path
):
    cfg = policy_config(settings, tmp_path)
    cfg.retention_policy_file = ""
    ids = seed(cfg)
    with get_session_factory(cfg)() as session:
        set_hold(session, "conversation", ids["conversation"], "CASE-SYNTHETIC")
        session.commit()
    with TestClient(create_app(cfg)) as client:
        login = client.post(
            "/api/v1/auth/login",
            json={"email": "retention-owner@example.com", "password": "Synthetic#Credential2026"},
        )
        headers = {"Authorization": "Bearer " + login.json()["access_token"]}
        path = f"/api/v1/chat/conversations/{ids['conversation']}"
        assert client.delete(path, headers=headers).status_code == 422
        with get_session_factory(cfg)() as session:
            set_hold(session, "conversation", ids["conversation"], "CASE-SYNTHETIC", release=True)
            session.commit()
        assert client.delete(path, headers=headers).status_code == 204
        assert client.get(path, headers=headers).status_code == 404
        new = client.post("/api/v1/chat/conversations", headers=headers, json={})
        assert new.json()["id"] > ids["conversation"]
    with get_session_factory(cfg)() as session:
        assert session.get(WorkflowTask, ids["workflow"]).conversation_id is None


def owned_snapshot(cfg, folder, identity, *, old=True):
    snapshot = folder / ("retention-" + f"{identity:032x}" + ".db")
    result = backup(cfg.sqlite_path, snapshot)
    manifest = snapshot.with_name(snapshot.name + ".manifest.json")
    data = json.loads(manifest.read_text())
    data["retention_owner"] = retention.OWNER
    if old:
        data["created_at"] = (dt.datetime.now(dt.UTC) - dt.timedelta(days=30)).isoformat()
    manifest.write_text(json.dumps(data))
    return snapshot, manifest, result


def test_snapshot_expiry_preserves_holds_and_progresses_past_new_uuid_names(settings, tmp_path):
    cfg = policy_config(settings, tmp_path, backup_days=1)
    ids = seed(cfg)
    folder = backup_directory(cfg.retention_backup_dir)
    template, _, _ = owned_snapshot(cfg, folder, 1, old=False)
    # 101 fresh names before the expired one reproduced the original starvation.
    for identity in range(2, 102):
        copy = folder / ("retention-" + f"{identity:032x}" + ".db")
        copy.write_bytes(template.read_bytes())
        copy.with_name(copy.name + ".manifest.json").write_bytes(
            template.with_name(template.name + ".manifest.json").read_bytes()
        )
    expired, manifest, _ = owned_snapshot(cfg, folder, 102)
    with get_session_factory(cfg)() as session:
        set_hold(session, "audit", ids["audit"], "CASE-EXPIRY")
        session.commit()
        assert (
            prune_backups(
                session, folder, read_policy(cfg.retention_policy_file), dt.datetime.now(dt.UTC)
            )
            == 0
        )
        assert expired.exists()
        set_hold(session, "audit", ids["audit"], "CASE-EXPIRY", release=True)
        session.commit()
        assert (
            prune_backups(
                session, folder, read_policy(cfg.retention_policy_file), dt.datetime.now(dt.UTC)
            )
            == 1
        )
        assert not expired.exists() and not manifest.exists() and template.exists()
        assert session.scalar(select(AuditLog).where(AuditLog.action == "retention.backup_expired"))


def test_tampered_or_unowned_backups_are_not_removed(settings, tmp_path):
    cfg = policy_config(settings, tmp_path, backup_days=1)
    seed(cfg)
    folder = backup_directory(cfg.retention_backup_dir)
    snapshot, manifest, _ = owned_snapshot(cfg, folder, 1)
    snapshot.write_bytes(snapshot.read_bytes() + b"synthetic-change")
    with get_session_factory(cfg)() as session, pytest.raises(ValueError, match="changed"):
        prune_backups(
            session, folder, read_policy(cfg.retention_policy_file), dt.datetime.now(dt.UTC)
        )
    assert snapshot.exists() and manifest.exists()
    data = json.loads(manifest.read_text())
    data["retention_owner"] = "external-backup-tool"
    manifest.write_text(json.dumps(data))
    with get_session_factory(cfg)() as session:
        assert (
            prune_backups(
                session, folder, read_policy(cfg.retention_policy_file), dt.datetime.now(dt.UTC)
            )
            == 0
        )
    unowned = tmp_path / "operator-owned"
    unowned.mkdir()
    (unowned / "important.txt").write_text("synthetic")
    with pytest.raises(ValueError, match="not owned"):
        backup_directory(str(unowned))
    assert (unowned / "important.txt").read_text() == "synthetic"


def test_null_policy_keeps_all_data_and_repeated_cleanup_has_no_candidates(settings, tmp_path):
    cfg = policy_config(
        settings,
        tmp_path,
        **dict.fromkeys(
            [
                "conversations_days",
                "closed_tickets_days",
                "completed_workflows_days",
                "audit_days",
                "notifications_days",
                "backup_days",
            ]
        ),
    )
    ids = seed(cfg)
    assert not any(run_retention(cfg, apply=True)["counts"].values())
    with get_session_factory(cfg)() as session:
        assert session.get(Message, ids["message"]).content == "synthetic-private-message"
    cfg = policy_config(settings, tmp_path)
    assert all(value == 1 for value in run_retention(cfg, apply=True)["counts"].values())
    assert not any(run_retention(cfg, apply=True)["counts"].values())
    assert len(list((tmp_path / "backups").glob("retention-*.db"))) == 1


def test_sql_aggregates_exclude_erased_rows(settings, tmp_path):
    from app.services.dashboard_service import DashboardService

    cfg = policy_config(settings, tmp_path)
    seed(cfg)
    with get_session_factory(cfg)() as session:
        before = DashboardService().summary(session, days=180)
    run_retention(cfg, apply=True)
    with get_session_factory(cfg)() as session:
        after = DashboardService().summary(session, days=180)
    assert before["conversations"]["total"] == 1 and after["conversations"]["total"] == 0
    assert before["questions"]["total"] == 1 and after["questions"]["total"] == 0


@pytest.mark.parametrize("material", ["erased", "hold"])
def test_schema_rollback_refuses_erasure_or_preservation_history(settings, tmp_path, material):
    from alembic import command

    from app.db.migrations import configuration, current_revision

    cfg = policy_config(settings, tmp_path)
    ids = seed(cfg)
    if material == "erased":
        run_retention(cfg, apply=True)
    else:
        with get_session_factory(cfg)() as session:
            set_hold(session, "audit", ids["audit"], "CASE-ROLLBACK")
            session.commit()
    engine = get_engine(cfg)
    config = configuration()
    with (
        pytest.raises(RuntimeError, match="Rollback refused"),
        engine.connect() as connection,
        connection.begin(),
    ):
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.downgrade(config, "20261012_03")
    assert current_revision(engine) == "20261013_04"
    if material == "hold":
        with get_session_factory(cfg)() as session:
            assert session.get(DataHold, ("audit", str(ids["audit"])))
