"""Real Compose acceptance in a filtered source snapshot and disposable volumes.

Run with backend/.venv's Python. Missing Docker is a failure, never a mock pass.
Only this run's randomly named Compose projects are cleaned up.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


def port() -> int:
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0))
        return int(handle.getsockname()[1])


def wait_ready(url: str, seconds: int = 180) -> None:
    deadline = time.monotonic() + seconds
    with httpx.Client(base_url=url, trust_env=False, timeout=5) as client:
        while time.monotonic() < deadline:
            try:
                if client.get("/api/v1/ready").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1)
    raise RuntimeError("Business readiness timed out")


def check_api(url: str) -> tuple[str, int]:
    with httpx.Client(base_url=url, trust_env=False, timeout=90) as client:
        response = client.get("/")
        response.raise_for_status()
        assert '<div id="root">' in response.text
        assert "Content-Security-Policy" in response.headers
        assert client.get("/api/v1/tickets").status_code == 401

        def login(role: str) -> dict[str, str]:
            result = client.post(
                "/api/v1/auth/login",
                json={"email": f"{role}@example.com", "password": "Demo@12345"},
            )
            result.raise_for_status()
            return {"Authorization": "Bearer " + result.json()["access_token"]}

        employee, security = login("employee"), login("security")
        result = client.post("/api/v1/chat/conversations", headers=employee, json={})
        result.raise_for_status()
        cid = result.json()["id"]

        def ask(content: str, key: str) -> dict:
            result = client.post(
                f"/api/v1/chat/conversations/{cid}/messages",
                headers=employee,
                json={"content": content, "client_request_id": key},
            )
            result.raise_for_status()
            return result.json()["assistant_message"]

        policy = ask("公司密码有什么要求？", "policy")
        assert policy["payload"]["grounded"] and policy["payload"]["source_documents"]
        suspicious = ask("我点击了可疑邮件里的链接。", "phishing")
        confirmed = ask("是的，我输入了验证码。", "confirm")
        assert confirmed["payload"]["risk_level"] in {"high", "critical"}
        ref = confirmed["payload"]["ticket_reference"]
        assert ref and suspicious["payload"]["ticket_reference"] == ref
        assert ask("是的，我输入了验证码。", "confirm")["id"] == confirmed["id"]
        assert client.get("/api/v1/knowledge/documents/KB-004", headers=employee).status_code == 404
        detail = client.get(f"/api/v1/tickets/{ref}", headers=security)
        detail.raise_for_status()
        assert not detail.json()["human_acknowledged"]
        accepted = client.patch(
            f"/api/v1/tickets/{ref}",
            headers=security,
            json={
                "status": "in_progress",
                "note": "Synthetic container triage accepted.",
            },
        )
        accepted.raise_for_status()
        assert accepted.json()["human_acknowledged"]
        return employee["Authorization"], cid


def run(output: Path) -> None:
    docker_binary = shutil.which("docker")
    if not docker_binary:
        raise RuntimeError("Docker CLI/engine unavailable; actual container acceptance cannot run")
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run([docker_binary, "info"], check=True, capture_output=True)  # noqa: S603 -- resolved operator Docker CLI
    version = subprocess.run(  # noqa: S603 -- resolved operator Docker CLI, fixed arguments
        [docker_binary, "version", "--format", "{{.Server.Version}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    evidence: dict = {
        "docker_engine": version,
        "source": "filtered working-source snapshot",
        "stages": [],
    }
    with tempfile.TemporaryDirectory(prefix="esaa-container-acceptance-") as temporary:
        snapshot = Path(temporary)
        for directory in ("backend", "frontend"):
            shutil.copytree(
                ROOT / directory,
                snapshot / directory,
                ignore=shutil.ignore_patterns(
                    ".venv*",
                    "node_modules",
                    "data",
                    "dist",
                    "coverage",
                    "logs",
                    "__pycache__",
                    ".pytest_cache",
                    ".mypy_cache",
                    ".ruff_cache",
                    "*.db*",
                    "*.xml",
                    ".env*",
                    ".coverage*",
                ),
            )
        shutil.copy2(ROOT / "docker-compose.yml", snapshot / "docker-compose.yml")
        for configured in (False, True):
            project = "esaa-acceptance-" + uuid.uuid4().hex[:12]
            http_port, api_port = port(), port()
            env = {
                **os.environ,
                "ESAA_HTTP_PORT": str(http_port),
                "ESAA_API_PORT": str(api_port),
                "NOTIFICATION_WEBHOOK_URL": "",
                "NOTIFICATION_LEAD_WEBHOOK_URL": "",
                "NOTIFICATION_SIGNING_SECRET": "",
                "NOTIFICATION_CA_BUNDLE_FILE": "",
                "NOTIFICATION_POLL_INTERVAL_SECONDS": "0",
                "RETENTION_POLICY_FILE": "",
                "RETENTION_BACKUP_DIR": "",
            }
            if configured:
                (snapshot / ".env").write_text(
                    "APP_ENV=development\nDEBUG=false\nAUTH_SECRET_KEY=synthetic-container-acceptance-signing-key-20261012\nLLM_PROVIDER=mock\nEMBEDDING_PROVIDER=tfidf\nDEMO_USER_PASSWORD=Demo@12345\nCHAT_RATE_LIMIT_PER_MINUTE=1000\n",
                    encoding="utf-8",
                )
            (snapshot / "acceptance.override.yml").write_text(
                f"services:\n  backend:\n    image: {project}-backend:local\n  frontend:\n    image: {project}-frontend:local\n",
                encoding="utf-8",
            )
            compose = [
                docker_binary,
                "compose",
                "--project-name",
                project,
                "-f",
                "docker-compose.yml",
                "-f",
                "acceptance.override.yml",
            ]

            def command(
                *args: str,
                _project: str = project,
                _compose: list[str] = compose,
                _env: dict[str, str] = env,
            ) -> None:
                with (output / f"{_project}.log").open("a", encoding="utf-8") as log:
                    subprocess.run(  # noqa: S603 -- resolved Docker CLI and this run's generated resources
                        [*_compose, *args],
                        cwd=snapshot,
                        env=_env,
                        check=True,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )

            stage = {
                "configuration": "synthetic .env" if configured else "no .env",
                "project": project,
                "status": "failed",
            }
            evidence["stages"].append(stage)
            try:
                command("up", "--build", "--detach", "--wait", "--wait-timeout", "600")
                url = f"http://127.0.0.1:{http_port}"
                wait_ready(url)
                bearer, cid = check_api(url)
                command("restart", "backend")
                wait_ready(url)
                with httpx.Client(base_url=url, trust_env=False, timeout=10) as client:
                    headers = {"Authorization": bearer}
                    result = client.get(f"/api/v1/chat/conversations/{cid}", headers=headers)
                    if not configured:
                        assert result.status_code == 401  # documented ephemeral development key
                        auth = client.post(
                            "/api/v1/auth/login",
                            json={
                                "email": "employee@example.com",
                                "password": "Demo@12345",
                            },
                        ).json()
                        result = client.get(
                            f"/api/v1/chat/conversations/{cid}",
                            headers={"Authorization": "Bearer " + auth["access_token"]},
                        )
                    result.raise_for_status()
                    assert len(result.json()["messages"]) == 6
                (snapshot / "acceptance.override.yml").write_text(
                    f"services:\n  backend:\n    image: {project}-backend:local\n    environment:\n      KB_DIR: /app/data/synthetic-missing-kb\n  frontend:\n    image: {project}-frontend:local\n",
                    encoding="utf-8",
                )
                command("up", "--detach", "--no-deps", "backend")
                with httpx.Client(
                    base_url=f"http://127.0.0.1:{api_port}", trust_env=False, timeout=15
                ) as client:
                    deadline = time.monotonic() + 60
                    while True:
                        try:
                            alive = client.get("/api/v1/health")
                            if alive.status_code == 200 and alive.json()["status"] == "degraded":
                                break
                        except httpx.HTTPError:
                            pass
                        if time.monotonic() >= deadline:
                            raise RuntimeError(
                                "Unavailable KB fault did not produce degraded liveness"
                            )
                        time.sleep(1)
                    assert client.get("/api/v1/ready").status_code == 503
                    auth = client.post(
                        "/api/v1/auth/login",
                        json={
                            "email": "employee@example.com",
                            "password": "Demo@12345",
                        },
                    )
                    auth.raise_for_status()
                    headers = {"Authorization": "Bearer " + auth.json()["access_token"]}
                    conversation = client.post(
                        "/api/v1/chat/conversations", headers=headers, json={}
                    )
                    conversation.raise_for_status()
                    incident = client.post(
                        f"/api/v1/chat/conversations/{conversation.json()['id']}/messages",
                        headers=headers,
                        json={
                            "content": "I entered my password on a phishing page.",
                            "client_request_id": "kb-down",
                        },
                    )
                    incident.raise_for_status()
                    payload = incident.json()["assistant_message"]["payload"]
                    assert payload["ticket_reference"] and not payload["grounded"]
                stage["status"] = "passed"
                stage["checks"] = [
                    "SPA/CSP/proxy",
                    "Chinese policy",
                    "multi-turn escalation",
                    "idempotency",
                    "RBAC",
                    "human acknowledgment",
                    "restart persistence",
                    "KB-failure readiness",
                    "KB-failure incident persistence",
                ]
            finally:
                # Names are generated by this function and never taken from user
                # input. No existing project, image or volume is deleted.
                command("down", "--volumes", "--remove-orphans")
                (output / "container-acceptance.json").write_text(
                    json.dumps(evidence, ensure_ascii=False, indent=2), encoding="utf-8"
                )
    print(json.dumps(evidence, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "logs" / "container-acceptance")
    run(parser.parse_args().output.resolve())
