"""Isolated offline/live acceptance; real modes require an explicit call budget.

Provider keys are read from .env, never arguments or report output. A live run
only completes automated checks; answer support and safe advice need review.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))


class AcceptancePreflightError(ValueError):
    """Only locally authored, secret-free messages may be included in reports."""


def evaluate(mode: str, output: Path, max_cases: int, max_network_calls: int | None) -> dict:
    from app.core.config import Settings, get_settings

    original = Settings(_env_file=ROOT / ".env")
    live = mode != "offline"
    if live:
        if not original.llm_api_key:
            raise AcceptancePreflightError(
                "LLM_API_KEY is missing; no live provider acceptance was run."
            )
        if max_network_calls is None or max_network_calls < 13:
            raise AcceptancePreflightError(
                "Live acceptance requires --max-network-calls >= 13 (explicit budget)."
            )
        if mode == "llm_semantic" and not (original.embedding_api_key or original.llm_api_key):
            raise AcceptancePreflightError("Embedding key is missing.")
        # Conservatively allow three startup embedding attempts and at most ten
        # provider attempts per turn. No pricing assumption is made.
        max_cases = min(max_cases, (max_network_calls - 3) // 10)
    data_path = BACKEND / "tests" / "data" / "evaluation_questions.json"
    dataset = json.loads(data_path.read_text(encoding="utf-8"))
    entries = dataset["questions"][:max_cases]
    output.mkdir(parents=True, exist_ok=True)
    overrides = {
        "APP_ENV": "test",
        "DEBUG": "false",
        "LOG_LEVEL": "WARNING",
        "AUTH_SECRET_KEY": "synthetic-acceptance-key-not-valid-outside-evaluation",
        "ALLOW_DEMO_LOGIN": "true",
        "SEED_DEMO_USERS": "true",
        "DEMO_USER_PASSWORD": "Demo@12345",
        "PASSWORD_HASH_ROUNDS": "4",
        "WORKFLOW_RETRY_INTERVAL_SECONDS": "0",
        "NOTIFICATION_WEBHOOK_URL": "",
        "NOTIFICATION_LEAD_WEBHOOK_URL": "",
        "NOTIFICATION_SIGNING_SECRET": "",
        "NOTIFICATION_CA_BUNDLE_FILE": "",
        "NOTIFICATION_POLL_INTERVAL_SECONDS": "0",
        "RETENTION_POLICY_FILE": "",
        "RETENTION_BACKUP_DIR": "",
        "CHAT_RATE_LIMIT_PER_MINUTE": "10000",
        "CHAT_MAX_MODEL_API_CALLS": "10",
        "LLM_MAX_RETRIES": "2",
        "LLM_PROVIDER": "openai_compatible" if live else "mock",
        "EMBEDDING_PROVIDER": "openai_compatible" if mode == "llm_semantic" else "tfidf",
        "KB_DIR": str(BACKEND / "knowledge_base"),
        "VECTOR_STORE": "memory",
    }
    previous = {
        key: os.environ.get(key) for key in (*overrides, "DATABASE_URL", "VECTOR_STORE_PATH")
    }
    results = []
    try:
        with tempfile.TemporaryDirectory(prefix="esaa-model-acceptance-") as folder:
            overrides["DATABASE_URL"] = "sqlite:///" + (Path(folder) / "acceptance.db").as_posix()
            overrides["VECTOR_STORE_PATH"] = str(Path(folder) / "index")
            os.environ.update(overrides)
            get_settings.cache_clear()
            from fastapi.testclient import TestClient

            from app.main import create_app
            from app.security.redaction import redact_credentials

            settings = get_settings()
            headers = {}
            with TestClient(create_app(settings), raise_server_exceptions=False) as client:
                ready = client.get("/api/v1/ready")
                if ready.status_code != 200:
                    raise RuntimeError(
                        "Index/provider initialization failed; readiness is not 200."
                    )
                for entry in entries:
                    role = entry["role"]
                    if role not in headers:
                        auth = client.post(
                            "/api/v1/auth/login",
                            json={"email": f"{role}@example.com", "password": "Demo@12345"},
                        )
                        auth.raise_for_status()
                        headers[role] = {"Authorization": "Bearer " + auth.json()["access_token"]}
                    created = client.post(
                        "/api/v1/chat/conversations", headers=headers[role], json={}
                    )
                    created.raise_for_status()
                    started = time.monotonic()
                    response = client.post(
                        f"/api/v1/chat/conversations/{created.json()['id']}/messages",
                        headers=headers[role],
                        json={"content": entry["question"], "client_request_id": entry["id"]},
                    )
                    response.raise_for_status()
                    payload = response.json()["assistant_message"]["payload"]
                    expected = entry["expected"]
                    sources = {source["document_id"] for source in payload["source_documents"]}
                    allowed = {
                        doc["document_id"]
                        for doc in client.get(
                            "/api/v1/knowledge/documents", headers=headers[role]
                        ).json()["documents"]
                    }
                    checks = {
                        "intent": payload["intent"] == expected["intent"],
                        "risk": payload["risk_level"] == expected["risk_level"],
                        "escalation": payload["human_escalation"] == expected["escalation"],
                        "ticket": bool(payload["ticket_reference"]) == expected["ticket"],
                        "blocking": payload["blocked"] == expected["blocked"],
                        "rbac": sources <= allowed,
                        "retrieval": not expected.get("documents_any_of")
                        or bool(sources & set(expected["documents_any_of"])),
                    }
                    results.append(
                        {
                            "id": entry["id"],
                            "role": role,
                            "question": entry["question"],
                            "checks": checks,
                            "expected": expected,
                            "payload": {**payload, "answer": redact_credentials(payload["answer"])},
                            "latency_seconds": round(time.monotonic() - started, 4),
                        }
                    )
            latency = [row["latency_seconds"] for row in results]
            metrics = (
                {
                    name: sum(row["checks"][name] for row in results) / len(results)
                    for name in results[0]["checks"]
                }
                if results
                else {}
            )
            critical_failures = [
                row["id"]
                for row in results
                if row["expected"]["risk_level"] in {"high", "critical"}
                and not all(row["checks"][key] for key in ("risk", "escalation", "ticket"))
            ]
            automatic_ok = (
                not critical_failures
                and metrics.get("intent", 0) >= 0.9
                and metrics.get("risk", 0) >= 0.9
                and metrics.get("retrieval", 0) >= 0.85
                and all(
                    metrics.get(name) == 1 for name in ("escalation", "ticket", "blocking", "rbac")
                )
            )
            endpoint = urlsplit(settings.llm_base_url)
            online_answers = sum(not row["payload"]["offline"] for row in results)
            if live and online_answers == 0:
                automatic_ok = False
            report = {
                "mode": mode,
                "status": "automated_checks_passed_manual_review_pending"
                if live and automatic_ok
                else "passed"
                if automatic_ok
                else "failed",
                "dataset_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
                "case_count": len(results),
                "model": settings.llm_model if live else "offline-extractive-v1",
                "endpoint_host": endpoint.hostname if live else None,
                "embedding_model": settings.embedding_model if mode == "llm_semantic" else "tfidf",
                "maximum_network_attempts": max_cases * 10 + (3 if mode == "llm_semantic" else 0)
                if live
                else 0,
                "estimated_cost": None,
                "cost_note": "Vendor pricing and failed-attempt charges require provider records; no cost estimate is fabricated.",
                "metrics": metrics,
                "critical_failures": critical_failures,
                "online_answers": online_answers,
                "fallback_answers": sum(
                    row["payload"]["provider"] == "offline-fallback" for row in results
                ),
                "latency_p50": statistics.median(latency) if latency else None,
                "latency_p95": sorted(latency)[max(0, math.ceil(len(latency) * 0.95) - 1)]
                if latency
                else None,
                "results": results,
            }
            (output / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            with (output / "answer-review.csv").open(
                "w", encoding="utf-8-sig", newline=""
            ) as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    [
                        "id",
                        "role",
                        "question",
                        "answer",
                        "sources",
                        "supported",
                        "safe_actions",
                        "reviewer",
                        "notes",
                    ]
                )
                for row in results:
                    writer.writerow(
                        [
                            row["id"],
                            row["role"],
                            row["question"],
                            row["payload"]["answer"],
                            ";".join(
                                source["document_id"]
                                for source in row["payload"]["source_documents"]
                            ),
                            "",
                            "",
                            "",
                            "",
                        ]
                    )
            return {key: value for key, value in report.items() if key != "results"}
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode", choices=("offline", "llm_tfidf", "llm_semantic"), default="offline"
    )
    parser.add_argument("--max-cases", type=int, default=40)
    parser.add_argument("--max-network-calls", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.max_cases < 1:
        parser.error("--max-cases must be positive")
    output = args.output or ROOT / "logs" / "model-acceptance" / (
        args.mode + "-" + dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    )
    try:
        report = evaluate(args.mode, output.resolve(), args.max_cases, args.max_network_calls)
    except Exception as exc:
        output.mkdir(parents=True, exist_ok=True)
        # Exception text can contain provider details. Persist a bounded category.
        report = {
            "mode": args.mode,
            "status": "not_completed",
            "error_type": type(exc).__name__,
            "reason": str(exc)
            if isinstance(exc, AcceptancePreflightError)
            else "Initialization or request failed; inspect redacted application logs.",
        }
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
