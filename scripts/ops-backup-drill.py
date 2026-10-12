"""Exercise SQLite recovery using simulated ESAA schema/data and committed WAL."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


def run(output: Path) -> dict:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.core.enums import MessageRole, Role, Severity, TicketStatus
    from app.db.migrations import upgrade_database
    from app.db.models import Conversation, Message, Ticket, User, WorkflowTask

    specification = importlib.util.spec_from_file_location(
        "ops_backup", ROOT / "scripts" / "ops-backup.py"
    )
    assert specification and specification.loader
    operation = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(operation)
    output.mkdir(parents=True, exist_ok=False)
    source, snapshot, restored = [
        output / name for name in ("source.db", "backup.db", "restored.db")
    ]
    with closing(sqlite3.connect(source)) as writer:
        writer.execute("PRAGMA journal_mode=WAL")
        engine = create_engine("sqlite:///" + source.as_posix())
        try:
            upgrade_database(engine)
            with Session(engine) as session:
                user = User(
                    email="recovery@example.com",
                    full_name="Simulated Recovery User",
                    password_hash="synthetic-hash-not-a-real-credential",  # noqa: S106 -- isolated simulated data
                    role=Role.EMPLOYEE,
                )
                session.add(user)
                session.flush()
                conversation = Conversation(
                    user_id=user.id, title="Simulated recovery incident"
                )
                session.add(conversation)
                session.flush()
                message = Message(
                    conversation_id=conversation.id,
                    role=MessageRole.USER,
                    content="Simulated phishing report; no real credentials.",
                )
                session.add(message)
                session.flush()
                ticket = Ticket(
                    reference="SEC-999001",
                    title="Simulated recovery ticket",
                    description="Synthetic data only",
                    category="security",
                    severity=Severity.HIGH,
                    status=TicketStatus.ESCALATED,
                    created_by_user_id=user.id,
                    conversation_id=conversation.id,
                )
                session.add(ticket)
                session.add(
                    WorkflowTask(
                        id="synthetic-recovery-task",
                        user_message_id=message.id,
                        conversation_id=conversation.id,
                        created_by_user_id=user.id,
                        status="pending",
                        snapshot={"simulated": True},
                    )
                )
                session.commit()
            # Keep this connection open to ensure a committed WAL update is
            # present during backup, rather than testing only a closed DB file.
            writer.execute(
                "UPDATE messages SET content=?", ("Committed WAL recovery evidence",)
            )
            writer.commit()
            assert source.with_name(source.name + "-wal").exists()
            backup_result = operation.backup(source, snapshot)
            restore_result = operation.restore(snapshot, restored)
            with closing(sqlite3.connect(restored)) as recovered:
                assert (
                    recovered.execute("SELECT content FROM messages").fetchone()[0]
                    == "Committed WAL recovery evidence"
                )
                assert (
                    recovered.execute("SELECT reference FROM tickets").fetchone()[0]
                    == "SEC-999001"
                )
                assert (
                    recovered.execute("SELECT status FROM workflow_tasks").fetchone()[0]
                    == "pending"
                )
            original_digest = operation.sha256(source)
            try:
                operation.restore(snapshot, source)
            except FileExistsError:
                pass
            else:
                raise AssertionError("Restore overwrote an existing database")
            assert operation.sha256(source) == original_digest
            with closing(sqlite3.connect(snapshot)) as modified:
                modified.execute("UPDATE messages SET content='Simulated tampering'")
                modified.commit()
            try:
                operation.restore(snapshot, output / "tampered-restore.db")
            except ValueError:
                pass
            else:
                raise AssertionError("Tampered backup was accepted")
            assert not (output / "tampered-restore.db").exists()
        finally:
            engine.dispose()
    report = {
        "status": "passed",
        "scope": "SQLite backup/restore drill; simulated ESAA data only",
        "checks": [
            "committed_WAL",
            "schema_and_row_counts",
            "pending_workflow_survives",
            "ticket_reference_survives",
            "existing_database_unchanged",
            "tampered_backup_refused",
        ],
        "backup": backup_result,
        "restore": restore_result,
        "note": "The backup was deliberately tampered with after successful restore; do not reuse it. Production backup directory ACLs, signing secrets, migration/rollback and restore startup still require separate acceptance.",
    }
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(run(arguments.output.resolve()), ensure_ascii=False, indent=2))
