"""External API patrol. JSON stdout/exit status are inputs to an operator's alert sink."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ssl
import time
from urllib.parse import urlsplit

import httpx


def patrol(base_url: str, email: str, password: str, *, ca_file: str = "") -> tuple[dict, int]:
    """Probe actual API readiness and authenticated gauges; never echo responses/errors."""
    parsed = urlsplit(base_url)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or not parsed.hostname
        or not (
            parsed.scheme == "https"
            or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
        )
    ):
        return {"state": "error", "alerts": ["monitor_configuration_invalid"]}, 2
    if not email or not password:
        return {"state": "error", "alerts": ["monitor_credentials_missing"]}, 2
    result = {"generated_at": dt.datetime.now(dt.UTC).isoformat(), "alerts": []}
    started = time.monotonic()
    try:
        with httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=10,
            trust_env=False,
            follow_redirects=False,
            verify=ssl.create_default_context(cafile=ca_file) if ca_file else True,
        ) as client:
            ready = client.get("/api/v1/ready")
            if ready.status_code != 200:
                result["alerts"].append("service_not_ready")
            login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
            login.raise_for_status()
            token = login.json()["access_token"]
            client.headers["Authorization"] = f"Bearer {token}"
            try:
                status = client.get("/api/v1/operations/status")
                status.raise_for_status()
                body = status.json()
                # Only schema-constrained, known fields leave the patrol. Never
                # print an error response or an arbitrary upstream object.
                allowed = {
                    "knowledge_unavailable",
                    "high_risk_notification_missing",
                    "notification_receiver_unconfigured",
                    "workflow_backlog_over_5m",
                    "notification_backlog_over_5m",
                    "notification_retry_exhausted",
                    "high_risk_response_overdue",
                    "model_failures_last_hour",
                    "workflow_failures_last_hour",
                }
                codes = body["alerts"]
                if not isinstance(codes, list) or any(code not in allowed for code in codes):
                    raise ValueError("invalid status schema")
                result["alerts"].extend(codes)
            finally:
                client.post("/api/v1/auth/logout")
        result["state"] = "alert" if result["alerts"] else "ok"
        code = 1 if result["alerts"] else 0
    except Exception as exc:
        result["state"] = "error"
        result["alerts"].append("monitor_probe_failed")
        result["error_type"] = type(exc).__name__
        code = 2
    result["probe_duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result, code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once", action="store_true", help="one patrol; exit 0 ok, 1 alerts, 2 failed"
    )
    parser.add_argument("--interval", type=int, default=300)
    args = parser.parse_args()
    if args.interval < 60:
        parser.error("interval must be at least 60 seconds")
    previous = None
    while True:
        result, code = patrol(
            os.environ.get("ESAA_MONITOR_BASE_URL", "http://127.0.0.1:8110"),
            os.environ.get("ESAA_MONITOR_EMAIL", ""),
            os.environ.get("ESAA_MONITOR_PASSWORD", ""),
            ca_file=os.environ.get("ESAA_MONITOR_CA_FILE", ""),
        )
        state = (result["state"], tuple(result["alerts"]))
        if args.once or state != previous:
            print(json.dumps(result), flush=True)
        if args.once:
            return code
        previous = state
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
