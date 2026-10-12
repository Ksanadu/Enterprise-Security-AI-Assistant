"""Family-isolated quality evaluation against the complete offline API pipeline."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))
RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def evaluation_status(gate: bool | None, *, regression: bool, subset: bool) -> str:
    if subset:
        return "diagnostic_subset"
    if gate is None:
        return "baseline_measured"
    if not gate:
        return "failed"
    return "regression_passed" if regression else "passed"


def run(split: str, output: Path, limit: int | None = None) -> dict:
    thresholds_path = BACKEND / "evaluation" / "thresholds-v1.json"
    thresholds = json.loads(thresholds_path.read_text()) if thresholds_path.exists() else None
    if split == "validation" and thresholds is None:
        raise ValueError("Freeze thresholds after the development baseline, before validation.")
    if limit is not None and limit < 1:
        raise ValueError("Evaluation limit must be positive.")
    if split == "validation" and limit is not None:
        raise ValueError("Validation acceptance requires the complete frozen split.")
    path = BACKEND / "evaluation" / "frozen-v1.json"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != path.with_suffix(".sha256").read_text().strip():
        raise ValueError("Frozen dataset checksum changed; review a new version before evaluation.")
    if thresholds is not None and thresholds["dataset_sha256"] != digest:
        raise ValueError("Thresholds were frozen for a different dataset.")
    dataset = json.loads(path.read_text(encoding="utf-8"))
    usage_path = BACKEND / "evaluation" / "validation-use-v1.json"
    usage = json.loads(usage_path.read_text()) if usage_path.exists() else {}
    if usage and usage["dataset_sha256"] != digest:
        raise ValueError("Validation-use record refers to a different dataset.")
    regression = split == "validation" and usage.get("validation_used_for_tuning", False)
    cases = [case for case in dataset["single_turn"] if case["split"] == split]
    groups = [case for case in dataset["multi_turn"] if case["split"] == split]
    if limit is not None:
        cases, groups = cases[:limit], groups[:limit]
    overrides = {
        "APP_ENV": "test",
        "DEBUG": "false",
        "LOG_LEVEL": "ERROR",
        "LOG_FORMAT": "json",
        "AUTH_SECRET_KEY": "synthetic-quality-evaluation-signing-key-not-for-production",
        "ALLOW_DEMO_LOGIN": "true",
        "SEED_DEMO_USERS": "true",
        "DEMO_USER_PASSWORD": "Demo@12345",
        "PASSWORD_HASH_ROUNDS": "4",
        "LLM_PROVIDER": "mock",
        "EMBEDDING_PROVIDER": "tfidf",
        "VECTOR_STORE": "memory",
        "KB_DIR": str(BACKEND / "knowledge_base"),
        "CHAT_RATE_LIMIT_PER_MINUTE": "10000",
        "WORKFLOW_RETRY_INTERVAL_SECONDS": "0",
        "NOTIFICATION_WEBHOOK_URL": "",
        "NOTIFICATION_LEAD_WEBHOOK_URL": "",
        "NOTIFICATION_SIGNING_SECRET": "",
        "NOTIFICATION_CA_BUNDLE_FILE": "",
        "NOTIFICATION_POLL_INTERVAL_SECONDS": "0",
        "RETENTION_POLICY_FILE": "",
        "RETENTION_BACKUP_DIR": "",
    }
    previous = {
        key: os.environ.get(key) for key in (*overrides, "DATABASE_URL", "VECTOR_STORE_PATH")
    }
    results, dialogues = [], []
    from app.core.config import get_settings

    try:
        with tempfile.TemporaryDirectory(prefix="esaa-quality-evaluation-") as temporary:
            overrides.update(
                DATABASE_URL="sqlite:///" + (Path(temporary) / "quality.db").as_posix(),
                VECTOR_STORE_PATH=str(Path(temporary) / "index"),
            )
            os.environ.update(overrides)
            get_settings.cache_clear()
            from fastapi.testclient import TestClient

            from app.main import create_app

            headers, scopes = {}, {}
            with TestClient(create_app(get_settings()), raise_server_exceptions=False) as client:
                for role in ("employee", "it", "security"):
                    response = client.post(
                        "/api/v1/auth/login",
                        json={"email": f"{role}@example.com", "password": "Demo@12345"},
                    )
                    response.raise_for_status()
                    headers[role] = {"Authorization": "Bearer " + response.json()["access_token"]}
                    scopes[role] = {
                        row["document_id"]
                        for row in client.get(
                            "/api/v1/knowledge/documents", headers=headers[role]
                        ).json()["documents"]
                    }

                def conversation(role):
                    response = client.post(
                        "/api/v1/chat/conversations", headers=headers[role], json={}
                    )
                    response.raise_for_status()
                    return response.json()["id"]

                def ask(role, cid, question, key):
                    started = time.monotonic()
                    response = client.post(
                        f"/api/v1/chat/conversations/{cid}/messages",
                        headers=headers[role],
                        json={"content": question, "client_request_id": key},
                    )
                    response.raise_for_status()
                    return response.json()["assistant_message"][
                        "payload"
                    ], time.monotonic() - started

                for case in cases:
                    role, expected = case["role"], case["expected"]
                    payload, latency = ask(role, conversation(role), case["question"], case["id"])
                    documents = {row["document_id"] for row in payload["source_documents"]}
                    checks = {
                        "intent": payload["intent"] == expected["intent"],
                        "risk": expected["risk_level"] is None
                        or payload["risk_level"] == expected["risk_level"],
                        "escalation": payload["human_escalation"] == expected["escalation"],
                        "blocking": payload["blocked"] == expected["blocked"],
                        "rbac": documents <= scopes[role],
                        "retrieval": not expected["documents_any_of"]
                        or bool(documents & set(expected["documents_any_of"])),
                        "delivery": not expected["escalation"] or bool(payload["ticket_reference"]),
                    }
                    results.append(
                        {
                            "id": case["id"],
                            "family": case["family"],
                            "language": case["language"],
                            "role": role,
                            "question": case["question"],
                            "expected": expected,
                            "actual_intent": payload["intent"],
                            "actual_risk": payload["risk_level"],
                            "checks": checks,
                            "documents": sorted(documents),
                            "ticket_reference": payload["ticket_reference"],
                            "latency_seconds": latency,
                            "answer": payload["answer"],
                            "recommended_actions": payload["recommended_actions"],
                        }
                    )
                for group in groups:
                    cid, observed, references, peak = conversation(group["role"]), [], set(), 0
                    for index, turn in enumerate(group["turns"]):
                        payload, latency = ask(
                            group["role"], cid, turn["question"], f"{group['id']}-{index}"
                        )
                        peak = max(peak, RANK[turn["risk_level"]])
                        if payload["ticket_reference"]:
                            references.add(payload["ticket_reference"])
                        observed.append(
                            {
                                "question": turn["question"],
                                "expected_risk": turn["risk_level"],
                                "actual_risk": payload["risk_level"],
                                "peak_risk": payload["peak_risk_level"],
                                "risk_ok": payload["risk_level"] == turn["risk_level"],
                                "peak_ok": RANK[payload["peak_risk_level"]] == peak,
                                "delivery_ok": RANK[turn["risk_level"]] < 2
                                or bool(payload["ticket_reference"]),
                                "latency_seconds": latency,
                            }
                        )
                    # Inspect stored conversation tickets, not just the references
                    # the model turn happened to return. Seed tickets are excluded.
                    from sqlalchemy import select

                    from app.db.models import Ticket
                    from app.db.session import session_scope

                    with session_scope() as session:
                        count = len(
                            session.scalars(
                                select(Ticket).where(Ticket.conversation_id == cid)
                            ).all()
                        )
                    expected_count = int(peak >= 1)
                    dialogues.append(
                        {
                            "id": group["id"],
                            "turns": observed,
                            "ticket_count": count,
                            "expected_ticket_count": expected_count,
                            "one_ticket_ok": count == expected_count and len(references) <= 1,
                            "passed": count == expected_count
                            and len(references) <= 1
                            and all(
                                row["risk_ok"] and row["peak_ok"] and row["delivery_ok"]
                                for row in observed
                            ),
                        }
                    )
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()
    confusion = {"intent": defaultdict(Counter), "risk": defaultdict(Counter)}
    for result in results:
        confusion["intent"][result["expected"]["intent"]][result["actual_intent"]] += 1
        if result["expected"]["risk_level"] is not None:
            confusion["risk"][result["expected"]["risk_level"]][result["actual_risk"]] += 1
    graded_risk = [row for row in results if row["expected"]["risk_level"] is not None]
    retrieval = [row for row in results if row["expected"]["documents_any_of"]]
    high = [row for row in graded_risk if RANK[row["expected"]["risk_level"]] >= 2]
    low = [row for row in graded_risk if row["expected"]["risk_level"] == "low"]

    def rate(rows, key):
        return sum(row["checks"][key] for row in rows) / len(rows) if rows else None

    high_recall = (
        sum(RANK[row["actual_risk"]] >= 2 and row["checks"]["delivery"] for row in high) / len(high)
        if high
        else None
    )
    latency = [row["latency_seconds"] for row in results]
    metrics = {
        "intent_accuracy": rate(results, "intent"),
        "risk_accuracy": rate(graded_risk, "risk"),
        "retrieval_recall_at_k": rate(retrieval, "retrieval"),
        "high_risk_delivery_recall": high_recall,
        "benign_high_false_positive_rate": sum(RANK[row["actual_risk"]] >= 2 for row in low)
        / len(low)
        if low
        else None,
        "rbac_violations": sum(not row["checks"]["rbac"] for row in results),
        "blocking_accuracy": rate(results, "blocking"),
        "multi_turn_accuracy": sum(row["passed"] for row in dialogues) / len(dialogues)
        if dialogues
        else None,
    }
    gate = (
        None
        if thresholds is None or limit is not None
        else all(
            metrics[name] is not None
            and (
                metrics[name] <= bound
                if name in {"benign_high_false_positive_rate", "rbac_violations"}
                else metrics[name] >= bound
            )
            for name, bound in thresholds["metrics"].items()
        )
    )
    hard_failures = [
        row["id"]
        for row in high
        if not all(
            row["checks"][key] for key in ("risk", "escalation", "delivery", "rbac", "blocking")
        )
    ]
    if gate is not None:
        gate = gate and not hard_failures
    by_language = {
        language: {
            "cases": len(rows := [row for row in results if row["language"] == language]),
            "intent_accuracy": rate(rows, "intent"),
            "risk_accuracy": rate(
                [row for row in rows if row["expected"]["risk_level"] is not None], "risk"
            ),
        }
        for language in ("zh", "en", "mixed")
    }
    per_class = {}
    for kind, matrix in confusion.items():
        labels = sorted(set(matrix) | {label for counts in matrix.values() for label in counts})
        per_class[kind] = {}
        for label in labels:
            true_positive = matrix.get(label, {}).get(label, 0)
            expected_count = sum(matrix.get(label, {}).values())
            predicted_count = sum(counts.get(label, 0) for counts in matrix.values())
            per_class[kind][label] = {
                "support": expected_count,
                "precision": true_positive / predicted_count if predicted_count else None,
                "recall": true_positive / expected_count if expected_count else None,
            }
    report = {
        "dataset_sha256": digest,
        "split": split,
        "mode": "offline",
        "purpose": "regression" if regression else split,
        "status": evaluation_status(gate, regression=regression, subset=limit is not None),
        "single_turn_count": len(results),
        "multi_turn_count": len(dialogues),
        "graded_risk_count": len(graded_risk),
        "graded_retrieval_count": len(retrieval),
        "annotation_review": dataset["annotation_review"],
        "answer_support_review": "pending; lexical/API checks do not establish semantic support",
        "metrics": metrics,
        "critical_case_failures": hard_failures,
        "by_language": by_language,
        "per_class": per_class,
        "confusion_matrices": {
            key: {label: dict(counts) for label, counts in matrix.items()}
            for key, matrix in confusion.items()
        },
        "latency_p50": statistics.median(latency) if latency else None,
        "latency_p95": sorted(latency)[max(0, math.ceil(len(latency) * 0.95) - 1)]
        if latency
        else None,
        "failures": [
            {"id": row["id"], "failed_checks": [key for key, ok in row["checks"].items() if not ok]}
            for row in results
            if not all(row["checks"].values())
        ],
        "dialogue_failures": [row["id"] for row in dialogues if not row["passed"]],
        "results": results,
        "dialogues": dialogues,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        key: value
        for key, value in report.items()
        if key not in {"results", "dialogues", "confusion_matrices"}
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("development", "validation"), default="development")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    output = args.output or ROOT / "logs" / "quality" / (
        args.split + "-" + dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    report = run(args.split, output, args.limit)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(1 if report["status"] == "failed" else 0)
